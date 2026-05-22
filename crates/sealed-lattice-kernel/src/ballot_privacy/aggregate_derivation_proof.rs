use std::collections::BTreeSet;

use super::*;

const AGGREGATE_DERIVATION_COMPONENT_ID: &str = "aggregate-derivation-component";
const AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID: &str =
    "aggregate-derivation-linear-compatibility-v1";
const AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID: &str =
    "aggregate-derivation-linear-proof-encoding-v1";
const AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT: &str =
    "sparse-polynomial-matrix-linear-proof-v1";
const AGGREGATE_DERIVATION_SOURCE_RING_DEGREE: usize = 256;
const AGGREGATE_DERIVATION_PROOF_RING_DEGREE: usize = 64;
const AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED: u128 = 3_000_000_000_000_000;
const AGGREGATE_DERIVATION_PROOF_MODULUS: u64 = 70_368_744_177_829;

pub(crate) fn generate_aggregate_derivation_proof_from_command_request(request: &Value) -> Value {
    let proof_input =
        match required_json_field(request, "proofInput", "generateAggregateDerivationProof") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "generateAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let secret_state =
        match required_json_field(request, "secretState", "generateAggregateDerivationProof") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "generateAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let prover_randomness_hex = match required_string_field(
        request,
        "proverRandomnessHex",
        "generateAggregateDerivationProof",
    ) {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "generateAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };

    let refused_objects = collect_aggregate_proof_input_refusals(proof_input, None, false);
    if !refused_objects.is_empty() {
        return structural_rejection("generateAggregateDerivationProof", refused_objects);
    }

    let generation =
        generate_aggregate_relation_proof(proof_input, secret_state, prover_randomness_hex);

    match generation {
        Ok(generation) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "generateAggregateDerivationProof",
            "componentId": AGGREGATE_DERIVATION_COMPONENT_ID,
            "statusLabels": [
                "AggregateDerivationRelationWitnessChecked",
                "AggregateDerivationProofBytesGenerated",
                "AggregateDerivationProofVerified"
            ],
            "acceptedDigests": [],
            "refusedObjects": [],
            "unresolvedReason": Value::Null,
            "generatedProofBytes": true,
            "proofBytesHex": generation.proof_hex,
            "proofSizeBytes": generation.proof_size_bytes,
            "summary": {
                "challengeHex": generation.challenge_hex,
                "relationCommitmentDigest": generation.relation_commitment_digest
            }
        }),
        Err(error) => structural_rejection(
            "generateAggregateDerivationProof",
            vec![error.to_json_value()],
        ),
    }
}

pub(crate) fn verify_aggregate_derivation_proof_from_command_request(request: &Value) -> Value {
    let Some(component) = request.get("component") else {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                "verifyAggregateDerivationProof.component is required for claim-bearing aggregate derivation verification.",
                None,
            )],
        );
    };
    let counted_ballot_packages = request.get("countedBallotPackages");
    let close_record = request.get("closeRecord");
    let contributor_action_context = request.get("contributorActionContext");
    let unsafe_small_roster_acknowledged = request
        .get("unsafeSmallRosterAcknowledged")
        .and_then(Value::as_bool)
        == Some(true)
        || request
            .get("casualMicroRosterAcknowledged")
            .and_then(Value::as_bool)
            == Some(true);
    let proof_input = match required_json_field(component, "proofInput", "component") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let object_digest = string_field(component, "aggregateDerivationComponentDigest")
        .or_else(|| string_field(proof_input, "statementDigest"));
    let mut refused_objects =
        collect_aggregate_proof_input_refusals(proof_input, Some(component), true);
    refused_objects.extend(collect_aggregate_component_refusals(component));
    refused_objects.extend(collect_aggregate_post_close_context_refusals(
        close_record,
        contributor_action_context,
        component,
    ));
    refused_objects.extend(collect_aggregate_counted_package_preflight_refusals(
        counted_ballot_packages,
        component,
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyAggregateDerivationProof", refused_objects);
    }

    let proof_statement = match required_json_field(proof_input, "proofStatement", "proofInput") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let parameter_set_value =
        match required_json_field(proof_input, "proofParameterSet", "proofInput") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let proof_encoding_value = match required_json_field(proof_input, "proofEncoding", "proofInput")
    {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    let public_randomness_hex =
        match required_string_field(proof_input, "publicRandomnessHex", "proofInput") {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let proof_hex = match required_string_field(proof_input, "proofBytesHex", "proofInput") {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };
    if let Err(error) =
        serde_json::from_value::<LinearProofParameterSet>(parameter_set_value.clone())
    {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!("Aggregate derivation parameter set is malformed: {error}"),
                object_digest,
            )],
        );
    }
    if let Err(error) = serde_json::from_value::<LinearProofEncoding>(proof_encoding_value.clone())
    {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!("Aggregate derivation proof encoding is malformed: {error}"),
                object_digest,
            )],
        );
    }
    let parsed_sparse_statement =
        match sparse_matrix_from_sparse_component_statement(proof_statement) {
            Ok(value) => value,
            Err(error) => {
                return component_proof_backend_rejection(
                    "verifyAggregateDerivationProof",
                    AGGREGATE_DERIVATION_COMPONENT_ID,
                    vec![json!({
                        "code": error.code,
                        "message": error.message,
                        "objectDigest": object_digest
                    })],
                    json!("BallotPackageInvalid"),
                );
            }
        };
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        match required_json_field(
            proof_statement,
            "targetCoefficientRepresentation",
            "proofInput.proofStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "Aggregate derivation target coefficient representation is malformed: {error}"
                ))
            })
        }) {
            Ok(value) => value,
            Err(error) => {
                return structural_rejection(
                    "verifyAggregateDerivationProof",
                    vec![error.to_json_value()],
                );
            }
        };
    let matrix_coefficient_representation = match matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofInput.proofStatement",
    ) {
        Ok(value) => value,
        Err(error) => {
            return structural_rejection(
                "verifyAggregateDerivationProof",
                vec![error.to_json_value()],
            );
        }
    };

    if let Err(error) = verify_aggregate_relation_proof(VerifyAggregateRelationProofInput {
        proof_statement,
        public_randomness_hex,
        proof_hex,
        source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
        target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
        matrix_coefficient_representation,
        target_coefficient_representation,
    }) {
        return structural_rejection(
            "verifyAggregateDerivationProof",
            vec![structural_refusal(
                format!(
                    "Aggregate derivation relation proof is invalid: {}",
                    error.message
                ),
                object_digest,
            )],
        );
    }

    let counted_package_refusals = collect_aggregate_counted_package_refusals(
        counted_ballot_packages,
        component,
        unsafe_small_roster_acknowledged,
    );
    if !counted_package_refusals.is_empty() {
        return structural_rejection("verifyAggregateDerivationProof", counted_package_refusals);
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyAggregateDerivationProof",
        "componentId": AGGREGATE_DERIVATION_COMPONENT_ID,
        "statusLabels": [
            "AggregateDerivationStructureVerified",
            "AggregateDerivationProofVerified"
        ],
        "acceptedDigests": object_digest.map(|digest| vec![digest]).unwrap_or_default(),
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

struct AggregateRelationProofGeneration {
    proof_hex: String,
    proof_size_bytes: usize,
    challenge_hex: String,
    relation_commitment_digest: String,
}

struct VerifyAggregateRelationProofInput<'a> {
    proof_statement: &'a Value,
    public_randomness_hex: &'a str,
    proof_hex: &'a str,
    source_statement_matrix: &'a SparsePolynomialMatrix,
    target_vector_coefficients: &'a [Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
}

struct ParsedAggregateRelationProof {
    challenge: u64,
    relation_commitment_vector: PolynomialVector,
    response_vector: PolynomialVector,
}

fn generate_aggregate_relation_proof(
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

    let mask_vector = sample_aggregate_mask_vector(
        source_ring,
        parsed_sparse_statement.source_statement_matrix.columns(),
        statement_digest,
        public_randomness_hex,
        prover_randomness_hex,
    )?;
    let relation_commitment_vector = parsed_sparse_statement
        .source_statement_matrix
        .multiply_vector(&mask_vector)?;
    let challenge = aggregate_relation_challenge_scalar(
        statement_digest,
        public_randomness_hex,
        relation_commitment_vector.entries(),
        source_ring.modulus(),
    )?;
    let response_vector =
        mask_plus_scaled_witness(source_ring, &mask_vector, &source_witness_vector, challenge)?;
    let proof_value = aggregate_relation_proof_value(
        statement_digest,
        public_randomness_hex,
        challenge,
        relation_commitment_vector.entries(),
        response_vector.entries(),
    );
    let proof_json = canonical_json(&proof_value)?;
    let relation_commitment_digest = derive_digest(
        "AggregateDerivationComponentDigest",
        &json!({
            "purpose": "aggregate-derivation-relation-commitment-v1",
            "relationCommitmentVector": canonical_polynomial_vector_value(relation_commitment_vector.entries())
        }),
    )
    .ok_or_else(|| invalid_preflight("aggregate relation commitment digest did not derive"))?;

    Ok(AggregateRelationProofGeneration {
        proof_hex: to_hex(proof_json.as_bytes()),
        proof_size_bytes: proof_json.len(),
        challenge_hex: format!("{challenge:016x}"),
        relation_commitment_digest,
    })
}

fn verify_aggregate_relation_proof(
    input: VerifyAggregateRelationProofInput<'_>,
) -> crate::encoding::CanonicalResult<()> {
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
    let recomputed_challenge = aggregate_relation_challenge_scalar(
        statement_digest,
        input.public_randomness_hex,
        parsed_proof.relation_commitment_vector.entries(),
        source_ring.modulus(),
    )?;
    if recomputed_challenge != parsed_proof.challenge {
        return Err(invalid_preflight(
            "aggregate derivation proof challenge does not match its relation commitment",
        ));
    }
    let response_relation_output = input
        .source_statement_matrix
        .multiply_vector(&parsed_proof.response_vector)?;
    let scaled_target_vector =
        scale_polynomial_vector(source_ring, &target_vector, parsed_proof.challenge)?;
    let verification_left = response_relation_output.add(&scaled_target_vector)?;
    if verification_left.entries() != parsed_proof.relation_commitment_vector.entries() {
        return Err(invalid_preflight(
            "aggregate derivation relation proof response does not satisfy the public statement",
        ));
    }

    Ok(())
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
) -> crate::encoding::CanonicalResult<PolynomialVector> {
    let entries = (0..vector_length)
        .map(|column_index| {
            sample_aggregate_mask_polynomial(
                source_ring,
                statement_digest,
                public_randomness_hex,
                prover_randomness_hex,
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
    column_index: usize,
) -> crate::encoding::CanonicalResult<Vec<u64>> {
    let mut coefficients = Vec::with_capacity(source_ring.degree());
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
                &column_index_bytes,
                &block_index_bytes,
            ],
        );
        for chunk in block.chunks_exact(8) {
            let mut value_bytes = [0_u8; 8];
            value_bytes.copy_from_slice(chunk);
            coefficients.push(u64::from_le_bytes(value_bytes) % source_ring.modulus());
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

fn aggregate_relation_challenge_scalar(
    statement_digest: &str,
    public_randomness_hex: &str,
    relation_commitment_vector: &[Vec<u64>],
    modulus: u64,
) -> crate::encoding::CanonicalResult<u64> {
    let commitment_value = canonical_polynomial_vector_value(relation_commitment_vector);
    let commitment_json = canonical_json(&commitment_value)?;
    let challenge_block = hash512(
        "sealed-lattice-root/aggregate-derivation-proof-challenge-v1",
        &[
            statement_digest.as_bytes(),
            public_randomness_hex.as_bytes(),
            commitment_json.as_bytes(),
        ],
    );
    let mut challenge_bytes = [0_u8; 8];
    challenge_bytes.copy_from_slice(&challenge_block[..8]);
    let mut challenge = u64::from_le_bytes(challenge_bytes) % modulus;
    if challenge == 0 {
        challenge = 1;
    }

    Ok(challenge)
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
    challenge: u64,
    relation_commitment_vector: &[Vec<u64>],
    response_vector: &[Vec<u64>],
) -> Value {
    json!({
        "objectType": "AggregateDerivationRelationProof",
        "objectVersion": 1,
        "challenge": challenge.to_string(),
        "publicRandomnessHex": public_randomness_hex,
        "relationCommitmentVector": canonical_polynomial_vector_value(relation_commitment_vector),
        "responseVector": canonical_polynomial_vector_value(response_vector),
        "statementDigest": statement_digest
    })
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
        || u64_object_field(&proof_value, "objectVersion") != Some(1)
        || string_field(&proof_value, "statementDigest") != Some(statement_digest)
        || string_field(&proof_value, "publicRandomnessHex") != Some(public_randomness_hex)
    {
        return Err(invalid_preflight(
            "aggregate derivation proof shell is not bound to the statement",
        ));
    }
    let challenge = parse_canonical_u64_decimal(
        string_field(&proof_value, "challenge")
            .ok_or_else(|| invalid_preflight("aggregate derivation proof challenge is required"))?,
        source_ring.modulus(),
    )?;
    let relation_commitment_vector = parse_polynomial_vector_value(
        required_json_field(
            &proof_value,
            "relationCommitmentVector",
            "AggregateDerivationRelationProof",
        )?,
        source_ring,
        expected_rows,
        "aggregate derivation relation commitment",
    )?;
    let response_vector = parse_polynomial_vector_value(
        required_json_field(
            &proof_value,
            "responseVector",
            "AggregateDerivationRelationProof",
        )?,
        source_ring,
        expected_columns,
        "aggregate derivation response",
    )?;

    Ok(ParsedAggregateRelationProof {
        challenge,
        relation_commitment_vector,
        response_vector,
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

fn collect_aggregate_proof_input_refusals(
    proof_input: &Value,
    component: Option<&Value>,
    proof_bytes_required: bool,
) -> Vec<Value> {
    let object_digest = component
        .and_then(|component_value| {
            string_field(component_value, "aggregateDerivationComponentDigest")
        })
        .or_else(|| string_field(proof_input, "statementDigest"));
    let mut refused_objects = Vec::new();
    if string_field(proof_input, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use aggregate-derivation-component.",
            object_digest,
        ));
    }
    if string_field(proof_input, "proofStatementFormat")
        != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must use sparse-polynomial-matrix-linear-proof-v1.",
            object_digest,
        ));
    }
    if proof_bytes_required {
        match string_field(proof_input, "proofBytesHex") {
            Some(proof_bytes_hex)
                if !proof_bytes_hex.is_empty()
                    && proof_bytes_hex.len().is_multiple_of(2)
                    && proof_bytes_hex
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)) => {}
            _ => refused_objects.push(structural_refusal(
                "Aggregate derivation proof bytes must be non-empty lowercase hexadecimal bytes.",
                object_digest,
            )),
        }
    }
    let Some(proof_statement) = proof_input.get("proofStatement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofStatement.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(parameter_set) = proof_input.get("proofParameterSet") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofParameterSet.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(proof_encoding) = proof_input.get("proofEncoding") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof input must include proofEncoding.",
            object_digest,
        ));

        return refused_objects;
    };
    let statement_rows = usize_object_field(proof_statement, "statementRows");
    let statement_columns = usize_object_field(proof_statement, "statementColumns");
    let share_vector_width =
        statement_rows.and_then(|rows| rows.checked_sub(SHARE_COMMITMENT_MODULE_RANK));
    let expected_columns = share_vector_width.and_then(|width| {
        width
            .checked_mul(3)?
            .checked_add(SHARE_COMMITMENT_OPENING_DIMENSION)
    });
    let expected_short_response_length = statement_columns.and_then(|columns| {
        columns
            .checked_mul(
                AGGREGATE_DERIVATION_SOURCE_RING_DEGREE / AGGREGATE_DERIVATION_PROOF_RING_DEGREE,
            )?
            .checked_add(1)
    });

    if string_field(proof_statement, "componentId") != Some(AGGREGATE_DERIVATION_COMPONENT_ID)
        || string_field(proof_statement, "parameterProfileId")
            != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(proof_statement, "proofStatementFormat")
            != Some(AGGREGATE_DERIVATION_PROOF_STATEMENT_FORMAT)
        || string_field(proof_statement, "projectionCoverage")
            != Some("aggregate-derivation-full-encoded-layout")
        || string_field(proof_statement, "matrixCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "targetCoefficientRepresentation")
            != Some("centeredSignedSourceModulus")
        || string_field(proof_statement, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(proof_statement, "sourceRingDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || statement_rows.is_none()
        || statement_columns.is_none()
        || expected_columns != statement_columns
        || u64_object_field(proof_statement, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation sparse proof statement shape is invalid.",
            object_digest,
        ));
    }
    let Some(share_vector_width) = share_vector_width else {
        return refused_objects;
    };
    if share_vector_width == 0
        || share_vector_width % (BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize) != 0
        || share_vector_width
            > usize::try_from(BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT)
                .ok()
                .and_then(|maximum_option_count| {
                    maximum_option_count
                        .checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION as usize)
                })
                .unwrap_or(0)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation must use the full scalar-plus-one-hot encoded layout.",
            object_digest,
        ));
    }
    if string_field(parameter_set, "profileId") != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(parameter_set, "coefficientModulus")
            != Some(&SHARE_COMMITMENT_MODULUS.to_string())
        || usize_object_field(parameter_set, "ringDegree")
            != Some(AGGREGATE_DERIVATION_SOURCE_RING_DEGREE)
        || usize_object_field(parameter_set, "proofSystemRingDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(parameter_set, "statementRows") != statement_rows
        || usize_object_field(parameter_set, "statementColumns") != statement_columns
        || u64_object_field(parameter_set, "witnessL2BoundSquared")
            != Some(AGGREGATE_DERIVATION_WITNESS_L2_BOUND_SQUARED as u64)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation parameter set is not bound to the proof statement.",
            object_digest,
        ));
    }
    if string_field(proof_encoding, "profileId")
        != Some(AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID)
        || u64_object_field(proof_encoding, "coefficientModulus")
            != Some(AGGREGATE_DERIVATION_PROOF_MODULUS)
        || usize_object_field(proof_encoding, "ringDegree")
            != Some(AGGREGATE_DERIVATION_PROOF_RING_DEGREE)
        || usize_object_field(proof_encoding, "shortResponseVectorLength")
            != expected_short_response_length
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof encoding is not bound to the proof statement.",
            object_digest,
        ));
    }
    if let Some(statement_digest) = string_field(proof_statement, "statementDigest") {
        let expected_statement_digest =
            derive_aggregate_sparse_linear_statement_digest(proof_statement);
        if expected_statement_digest.as_deref() != Some(statement_digest) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof statement digest does not match its canonical payload.",
                Some(statement_digest),
            ));
        }
        if string_field(proof_input, "componentProofStatementDigest") != Some(statement_digest) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation proof input is not bound to the proof statement digest.",
                Some(statement_digest),
            ));
        }
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation proof statement is missing statementDigest.",
            object_digest,
        ));
    }
    if let Some(component_value) = component
        && let Some(statement) = component_value.get("statement")
        && let Some(challenge_domain_digest) = string_field(statement, "challengeDomainDigest")
        && challenge_domain_digest.len() >= 64
        && string_field(proof_input, "publicRandomnessHex") != Some(&challenge_domain_digest[..64])
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation public randomness must be verifier-derived from the statement challenge domain.",
            object_digest,
        ));
    }

    refused_objects
}

fn derive_aggregate_sparse_linear_statement_digest(proof_statement: &Value) -> Option<String> {
    let statement_payload = value_without_field(proof_statement, "statementDigest")?;
    derive_digest(
        "ChallengeDomainDigest",
        &json!({
            "payload": statement_payload,
            "purpose": "aggregate-derivation-sparse-linear-proof-statement-v1"
        }),
    )
}

fn collect_aggregate_post_close_context_refusals(
    close_record: Option<&Value>,
    contributor_action_context: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };

    if let Some(close_record_value) = close_record {
        refused_objects.extend(collect_aggregate_close_record_refusals(
            close_record_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires closeRecord evidence for the voting-closed board head.",
            object_digest,
        ));
    }

    if let Some(action_context_value) = contributor_action_context {
        refused_objects.extend(collect_aggregate_action_context_refusals(
            action_context_value,
            statement,
            object_digest,
        ));
    } else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires contributorActionContext evidence.",
            object_digest,
        ));
    }

    refused_objects
}

fn derive_close_record_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "CloseRecordDigest",
        &json!({
            "boardPosition": u64_object_field(close_record, "boardPosition")?,
            "boardSequence": u64_object_field(close_record, "boardSequence")?,
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeKind": string_field(close_record, "closeKind")?,
            "closedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "objectType": string_field(close_record, "objectType")?,
            "objectVersion": u64_object_field(close_record, "objectVersion")?,
            "organizerIdentity": string_field(close_record, "organizerIdentity")?
        }),
    )
}

fn derive_post_voting_closed_context_digest_from_value(close_record: &Value) -> Option<String> {
    derive_digest(
        "PostVotingClosedContextDigest",
        &json!({
            "ceremonyId": string_field(close_record, "ceremonyId")?,
            "closeRecordDigest": string_field(close_record, "closeRecordDigest")?,
            "electionManifestDigest": string_field(close_record, "electionManifestDigest")?,
            "votingClosedBoardHeadDigest": string_field(close_record, "closedBoardHeadDigest")?
        }),
    )
}

fn collect_aggregate_close_record_refusals(
    close_record: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let close_record_digest = string_field(close_record, "closeRecordDigest");
    let mut refused_objects = Vec::new();
    let close_record_shape_is_valid = string_field(close_record, "objectType")
        == Some("CloseRecord")
        && u64_object_field(close_record, "objectVersion") == Some(1)
        && string_field(close_record, "closeKind") == Some("VotingClosed")
        && string_field(close_record, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(close_record, "electionManifestDigest").is_some()
        && string_field(close_record, "closedBoardHeadDigest").is_some()
        && string_field(close_record, "postVotingClosedContextDigest").is_some()
        && u64_object_field(close_record, "boardSequence").is_some()
        && u64_object_field(close_record, "boardPosition").is_some()
        && string_field(close_record, "organizerIdentity").is_some_and(|value| !value.is_empty());
    if !close_record_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence must be a canonical VotingClosed close record.",
            close_record_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_close_record_digest_from_value(close_record).as_deref() != close_record_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord digest does not match its canonical payload.",
            close_record_digest.or(object_digest),
        ));
    }
    let expected_post_context_digest =
        derive_post_voting_closed_context_digest_from_value(close_record);
    if expected_post_context_digest.as_deref()
        != string_field(close_record, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord does not bind the canonical post-voting closed context digest.",
            close_record_digest.or(object_digest),
        ));
    }
    if string_field(close_record, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(close_record, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || close_record_digest != string_field(statement, "closeRecordDigest")
        || string_field(close_record, "closedBoardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(close_record, "postVotingClosedContextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation closeRecord evidence is not bound to the aggregate statement voting-closed context.",
            close_record_digest.or(object_digest),
        ));
    }

    refused_objects
}

fn derive_action_context_digest_from_value(action_context: &Value) -> Option<String> {
    derive_digest(
        "ActionContextDigest",
        &json!({
            "acceptedRecoveryEpochUpdateDigest": action_context.get("acceptedRecoveryEpochUpdateDigest")?.clone(),
            "actionSequence": u64_object_field(action_context, "actionSequence")?,
            "boardHeadDigest": string_field(action_context, "boardHeadDigest")?,
            "boardSequence": u64_object_field(action_context, "boardSequence")?,
            "ceremonyId": string_field(action_context, "ceremonyId")?,
            "contextDigest": string_field(action_context, "contextDigest")?,
            "deviceEpoch": u64_object_field(action_context, "deviceEpoch")?,
            "electionManifestDigest": string_field(action_context, "electionManifestDigest")?,
            "recoveryEpoch": u64_object_field(action_context, "recoveryEpoch")?,
            "recoveryPolicyDigest": string_field(action_context, "recoveryPolicyDigest")?,
            "rosterExternalAcceptanceDigest": action_context.get("rosterExternalAcceptanceDigest")?.clone(),
            "signerIdentity": string_field(action_context, "signerIdentity")?
        }),
    )
}

fn collect_aggregate_action_context_refusals(
    action_context: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let action_context_digest = string_field(action_context, "actionContextDigest");
    let mut refused_objects = Vec::new();
    let action_context_shape_is_valid = action_context_digest.is_some()
        && string_field(action_context, "ceremonyId").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "electionManifestDigest").is_some()
        && string_field(action_context, "signerIdentity").is_some_and(|value| !value.is_empty())
        && string_field(action_context, "boardHeadDigest").is_some()
        && u64_object_field(action_context, "boardSequence").is_some()
        && u64_object_field(action_context, "recoveryEpoch").is_some()
        && u64_object_field(action_context, "deviceEpoch").is_some()
        && u64_object_field(action_context, "actionSequence").is_some()
        && string_field(action_context, "recoveryPolicyDigest").is_some()
        && action_context
            .get("acceptedRecoveryEpochUpdateDigest")
            .is_some()
        && action_context
            .get("rosterExternalAcceptanceDigest")
            .is_some()
        && string_field(action_context, "contextDigest").is_some();
    if !action_context_shape_is_valid {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence must be canonical.",
            action_context_digest.or(object_digest),
        ));

        return refused_objects;
    }

    if derive_action_context_digest_from_value(action_context).as_deref() != action_context_digest {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext digest does not match its canonical payload.",
            action_context_digest.or(object_digest),
        ));
    }
    if action_context_digest != string_field(statement, "contributorActionContextDigest")
        || string_field(action_context, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(action_context, "electionManifestDigest")
            != string_field(statement, "manifestDigest")
        || string_field(action_context, "signerIdentity")
            != string_field(statement, "contributorIdentity")
        || string_field(action_context, "boardHeadDigest")
            != string_field(statement, "votingClosedBoardHeadDigest")
        || string_field(action_context, "contextDigest")
            != string_field(statement, "postVotingClosedContextDigest")
        || action_context
            .get("rosterExternalAcceptanceDigest")
            .and_then(Value::as_str)
            != string_field(statement, "contributorRosterExternalAcceptanceDigest")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation contributorActionContext evidence is not bound to the aggregate statement contributor and post-close context.",
            action_context_digest.or(object_digest),
        ));
    }

    refused_objects
}

fn collect_aggregate_counted_package_preflight_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let Some(packages) = counted_ballot_packages.and_then(Value::as_array) else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires countedBallotPackages so the verifier can route the counted set through accepted M5 package verification.",
            object_digest,
        ));

        return refused_objects;
    };
    if packages.is_empty() {
        refused_objects.push(structural_refusal(
            "Aggregate derivation verification requires at least one counted ballot package.",
            object_digest,
        ));

        return refused_objects;
    }

    let mut seen_package_digests = BTreeSet::new();
    for package in packages {
        let package_digest = string_field(package, "ballotPackageDigest");
        let Some(package_digest) = package_digest else {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted package is missing ballotPackageDigest.",
                object_digest,
            ));
            continue;
        };
        if !seen_package_digests.insert(package_digest.to_string()) {
            refused_objects.push(structural_refusal(
                "Aggregate derivation counted ballot packages must not contain duplicates.",
                Some(package_digest),
            ));
        }

        let missing_field_names = [
            ("proofBytesHex", package.get("proofBytesHex")),
            ("linearStatement", package.get("linearStatement")),
            ("parameterSet", package.get("parameterSet")),
            ("proofEncoding", package.get("proofEncoding")),
            ("publicRandomnessHex", package.get("publicRandomnessHex")),
            (
                "componentBundleStatement",
                package.get("componentBundleStatement"),
            ),
            ("componentProofBundle", package.get("componentProofBundle")),
            ("componentProofInputs", package.get("componentProofInputs")),
        ]
        .into_iter()
        .filter_map(|(field_name, value)| value.is_none().then_some(field_name))
        .collect::<Vec<_>>();
        if !missing_field_names.is_empty() {
            refused_objects.push(structural_refusal(
                format!(
                    "Aggregate derivation counted ballot packages must carry proof-byte-bearing M5 verifier inputs; missing {}.",
                    missing_field_names.join(", ")
                ),
                Some(package_digest),
            ));
        }
    }

    refused_objects
}

fn collect_aggregate_counted_package_refusals(
    counted_ballot_packages: Option<&Value>,
    component: &Value,
    unsafe_small_roster_acknowledged: bool,
) -> Vec<Value> {
    let preflight_refusals =
        collect_aggregate_counted_package_preflight_refusals(counted_ballot_packages, component);
    if !preflight_refusals.is_empty() {
        return preflight_refusals;
    }

    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects = Vec::new();
    let packages = counted_ballot_packages
        .and_then(Value::as_array)
        .expect("counted package preflight guarantees an array");

    let Some(statement) = component.get("statement") else {
        return refused_objects;
    };
    let Some(aggregate_commitment) = component.get("aggregateCommitment") else {
        return refused_objects;
    };

    let mut ordered_packages = Vec::new();
    for package in packages {
        let package_digest = string_field(package, "ballotPackageDigest");
        let dynamic_roster_profile_evidence =
            object_map(package).and_then(|object| object.get("dynamicRosterProfileEvidence"));
        let verification = verify_claim_bearing_ballot_package(
            package,
            dynamic_roster_profile_evidence,
            unsafe_small_roster_acknowledged,
        );
        if verification.get("ok").and_then(Value::as_bool) != Some(true) {
            refused_objects.push(structural_refusal(
                format!(
                    "Aggregate derivation counted package must verify through the accepted M5 Rust/WASM verifier before inclusion. {}",
                    verification_refusal_summary(&verification)
                ),
                package_digest.or(object_digest),
            ));
        }
        ordered_packages.push(package);
    }
    ordered_packages.sort_by(|left_package, right_package| {
        string_field(left_package, "ballotPackageDigest")
            .unwrap_or("")
            .cmp(string_field(right_package, "ballotPackageDigest").unwrap_or(""))
    });

    refused_objects.extend(collect_counted_package_binding_refusals(
        &ordered_packages,
        statement,
        aggregate_commitment,
        object_digest,
    ));

    refused_objects
}

fn verification_refusal_summary(verification: &Value) -> String {
    let refusal_messages = verification
        .get("refusedObjects")
        .and_then(Value::as_array)
        .map(|refusals| {
            refusals
                .iter()
                .filter_map(|refusal| string_field(refusal, "message"))
                .collect::<Vec<_>>()
                .join(" ")
        })
        .unwrap_or_default();
    if !refusal_messages.is_empty() {
        return refusal_messages;
    }

    verification
        .get("unresolvedReason")
        .and_then(Value::as_str)
        .filter(|reason| !reason.is_empty())
        .unwrap_or("No verifier refusal detail was returned.")
        .to_string()
}

fn collect_counted_package_binding_refusals(
    ordered_packages: &[&Value],
    statement: &Value,
    aggregate_commitment: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(contributor_identity) = string_field(statement, "contributorIdentity") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor identity.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(contributor_roster_position) =
        positive_roster_position(statement, "contributorRosterPosition")
    else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement is missing contributor roster position.",
            object_digest,
        ));

        return refused_objects;
    };

    let mut package_digests = Vec::new();
    let mut expected_package_references = Vec::new();
    let mut share_commitment_vectors = Vec::new();
    for package in ordered_packages {
        if let Some(package_digest) = string_field(package, "ballotPackageDigest") {
            package_digests.push(Value::String(package_digest.to_string()));
        }
        refused_objects.extend(collect_counted_package_context_refusals(
            package,
            statement,
            object_digest,
        ));
        match package_reference_for_contributor(
            package,
            contributor_identity,
            contributor_roster_position,
        ) {
            Some(reference) => expected_package_references.push(reference),
            None => refused_objects.push(structural_refusal(
                "Aggregate derivation counted package does not address the contributor in both receiver-payload and share-commitment references.",
                string_field(package, "ballotPackageDigest").or(object_digest),
            )),
        }
        match share_commitment_vector_for_contributor(
            package,
            contributor_identity,
            contributor_roster_position,
        ) {
            Some(vector) => share_commitment_vectors.push(vector),
            None => refused_objects.push(structural_refusal(
                "Aggregate derivation counted package does not carry a valid public share commitment polynomial vector for the contributor.",
                string_field(package, "ballotPackageDigest").or(object_digest),
            )),
        }
    }

    let statement_package_references = array_field(statement, "packageReferences");
    if statement_package_references != Some(&expected_package_references) {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement package references are not derived from the accepted counted M5 packages.",
            object_digest,
        ));
    }

    if let Some(expected_ballot_set_digest) =
        derive_counted_package_ballot_set_digest(statement, package_digests)
        && string_field(statement, "ballotSetDigest") != Some(expected_ballot_set_digest.as_str())
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation ballot-set digest is not derived from the accepted counted M5 packages and post-close context.",
            object_digest,
        ));
    }

    if let Some(expected_commitment_vector) =
        summed_share_commitment_vector(&share_commitment_vectors)
    {
        let expected_commitment_value = Value::Array(
            expected_commitment_vector
                .iter()
                .map(|polynomial| {
                    Value::Array(
                        polynomial
                            .iter()
                            .map(|coefficient| Value::String(coefficient.clone()))
                            .collect(),
                    )
                })
                .collect(),
        );
        if aggregate_commitment.get("commitmentPolynomialVector")
            != Some(&expected_commitment_value)
        {
            refused_objects.push(structural_refusal(
                "Aggregate share commitment polynomial vector is not the homomorphic sum of the accepted counted package commitments addressed to the contributor.",
                string_field(aggregate_commitment, "aggregateShareCommitmentDigest").or(object_digest),
            ));
        }
        if let Some(share_commitment_profile_digest) =
            string_field(statement, "shareCommitmentProfileDigest")
            && let Some(expected_body_digest) = derive_digest(
                "AggregateShareCommitmentDigest",
                &json!({
                    "commitmentPolynomialVector": expected_commitment_vector,
                    "profileDigest": share_commitment_profile_digest,
                    "purpose": "aggregate-share-commitment-body-v1"
                }),
            )
            && string_field(aggregate_commitment, "commitmentBodyDigest")
                != Some(expected_body_digest.as_str())
        {
            refused_objects.push(structural_refusal(
                "Aggregate share commitment body digest is not derived from the accepted counted package commitment sum.",
                string_field(aggregate_commitment, "aggregateShareCommitmentDigest").or(object_digest),
            ));
        }
    }

    refused_objects
}

fn collect_counted_package_context_refusals(
    package: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let Some(ballot_statement) = package.get("ballotProofStatement") else {
        return refused_objects;
    };
    let context_fields = [
        "ceremonyId",
        "manifestDigest",
        "rosterDigest",
        "pollSpecDigest",
        "thresholdProfileDigest",
        "shareCommitmentProfileDigest",
        "receiverEncryptionProfileDigest",
        "ballotScoreEncodingProfileDigest",
        "ballotShareLayoutProfileDigest",
        "aggregateInputEncodingProfileDigest",
        "encodedShareVectorLayoutDigest",
        "encodedAggregateLayoutDigest",
        "shareCommitmentMessageBoundCertDigest",
    ];
    if context_fields.iter().any(|field_name| {
        string_field(ballot_statement, field_name) != string_field(statement, field_name)
    }) || usize_object_field(ballot_statement, "optionCount")
        != usize_object_field(statement, "optionCount")
        || usize_object_field(ballot_statement, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || array_field(ballot_statement, "receiverPublicKeys").map(Vec::len)
            != usize_object_field(statement, "participantCount")
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation counted package context does not match the aggregate statement context.",
            string_field(package, "ballotPackageDigest").or(object_digest),
        ));
    }

    refused_objects
}

fn package_reference_for_contributor(
    package: &Value,
    contributor_identity: &str,
    contributor_roster_position: u64,
) -> Option<Value> {
    let ballot_statement = package.get("ballotProofStatement")?;
    let payload_reference = array_field(ballot_statement, "receiverPayloads")?
        .iter()
        .find(|reference| {
            string_field(reference, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(reference, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;
    let commitment_reference = array_field(ballot_statement, "shareCommitments")?
        .iter()
        .find(|reference| {
            string_field(reference, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(reference, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;

    Some(json!({
        "ballotPackageDigest": string_field(package, "ballotPackageDigest")?,
        "ballotProofStatementDigest": string_field(ballot_statement, "ballotProofStatementDigest")?,
        "receiverPayloadCiphertextRoot": string_field(payload_reference, "receiverPayloadCiphertextRoot")?,
        "receiverPayloadDigest": string_field(payload_reference, "receiverPayloadDigest")?,
        "shareCommitmentDigest": string_field(commitment_reference, "shareCommitmentDigest")?
    }))
}

fn share_commitment_vector_for_contributor(
    package: &Value,
    contributor_identity: &str,
    contributor_roster_position: u64,
) -> Option<Vec<Vec<String>>> {
    let share_commitment = array_field(package, "shareCommitments")?
        .iter()
        .find(|commitment| {
            string_field(commitment, "receiverIdentity") == Some(contributor_identity)
                && positive_roster_position(commitment, "receiverRosterPosition")
                    == Some(contributor_roster_position)
        })?;

    commitment_polynomial_vector_from_value(share_commitment.get("commitmentPolynomialVector")?)
}

fn commitment_polynomial_vector_from_value(value: &Value) -> Option<Vec<Vec<String>>> {
    let vector = value.as_array()?;
    if vector.len() != SHARE_COMMITMENT_MODULE_RANK {
        return None;
    }

    vector
        .iter()
        .map(|polynomial| {
            let coefficients = polynomial.as_array()?;
            if coefficients.len() != SHARE_COMMITMENT_MODULE_DEGREE {
                return None;
            }
            coefficients
                .iter()
                .map(|coefficient| {
                    let coefficient_string = coefficient.as_str()?;
                    let coefficient_value = coefficient_string.parse::<u64>().ok()?;
                    if !unsigned_decimal_string(coefficient_string)
                        || coefficient_value >= SHARE_COMMITMENT_MODULUS
                    {
                        return None;
                    }

                    Some(coefficient_string.to_string())
                })
                .collect::<Option<Vec<_>>>()
        })
        .collect()
}

fn summed_share_commitment_vector(vectors: &[Vec<Vec<String>>]) -> Option<Vec<Vec<String>>> {
    if vectors.is_empty() {
        return None;
    }
    let mut summed_vector =
        vec![vec!["0".to_string(); SHARE_COMMITMENT_MODULE_DEGREE]; SHARE_COMMITMENT_MODULE_RANK];
    for vector in vectors {
        if vector.len() != SHARE_COMMITMENT_MODULE_RANK {
            return None;
        }
        for (polynomial_index, polynomial) in vector.iter().enumerate() {
            if polynomial.len() != SHARE_COMMITMENT_MODULE_DEGREE {
                return None;
            }
            for (coefficient_index, coefficient) in polynomial.iter().enumerate() {
                let left = summed_vector[polynomial_index][coefficient_index]
                    .parse::<u64>()
                    .ok()?;
                let right = coefficient.parse::<u64>().ok()?;
                let sum =
                    (u128::from(left) + u128::from(right)) % u128::from(SHARE_COMMITMENT_MODULUS);
                summed_vector[polynomial_index][coefficient_index] = sum.to_string();
            }
        }
    }

    Some(summed_vector)
}

fn derive_counted_package_ballot_set_digest(
    statement: &Value,
    package_digests: Vec<Value>,
) -> Option<String> {
    derive_digest(
        "BallotSetDigest",
        &json!({
            "ballotPackageDigests": package_digests,
            "closeRecordDigest": string_field(statement, "closeRecordDigest")?,
            "manifestDigest": string_field(statement, "manifestDigest")?,
            "pollSpecDigest": string_field(statement, "pollSpecDigest")?,
            "postVotingClosedContextDigest": string_field(statement, "postVotingClosedContextDigest")?,
            "purpose": "m6-post-close-counted-m5-ballot-set-v1",
            "rosterDigest": string_field(statement, "rosterDigest")?,
            "thresholdProfileDigest": string_field(statement, "thresholdProfileDigest")?,
            "votingClosedBoardHeadDigest": string_field(statement, "votingClosedBoardHeadDigest")?
        }),
    )
}

fn collect_aggregate_component_refusals(component: &Value) -> Vec<Value> {
    let object_digest = string_field(component, "aggregateDerivationComponentDigest");
    let mut refused_objects =
        collect_forbidden_witness_field_refusals(component, object_digest, "component");
    let Some(statement) = component.get("statement") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include statement.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(aggregate_commitment) = component.get("aggregateCommitment") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include aggregateCommitment.",
            object_digest,
        ));

        return refused_objects;
    };
    let Some(certificate) = component.get("shareCommitmentMessageBoundCert") else {
        refused_objects.push(structural_refusal(
            "Aggregate derivation component must include a no-wraparound certificate.",
            object_digest,
        ));

        return refused_objects;
    };

    refused_objects.extend(collect_aggregate_statement_refusals(
        statement,
        object_digest,
    ));
    refused_objects.extend(collect_aggregate_commitment_refusals(
        aggregate_commitment,
        statement,
        object_digest,
    ));
    refused_objects.extend(collect_aggregate_certificate_refusals(
        certificate,
        statement,
        object_digest,
    ));

    refused_objects
}

fn collect_aggregate_statement_refusals(
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let statement_digest = string_field(statement, "aggregateDerivationStatementDigest");
    let expected_statement_digest =
        value_without_field(statement, "aggregateDerivationStatementDigest").and_then(
            |statement_payload| {
                derive_digest(
                    "AggregateDerivationComponentDigest",
                    &json!({
                        "purpose": "aggregate-derivation-statement-v1",
                        "statement": statement_payload
                    }),
                )
            },
        );
    let option_count = u64_object_field(statement, "optionCount").unwrap_or(0);
    let participant_count = usize_object_field(statement, "participantCount").unwrap_or(0);
    let unsafe_small_roster_acknowledged = statement
        .get("unsafeSmallRosterAcknowledged")
        .and_then(Value::as_bool)
        .unwrap_or(false);
    let small_roster_acknowledgement_matches_policy =
        if participant_count < BALLOT_PRIVACY_MINIMUM_SAFE_PARTICIPANT_COUNT {
            unsafe_small_roster_acknowledged
        } else {
            !unsafe_small_roster_acknowledged
        };
    let share_vector_width = usize_object_field(statement, "shareVectorWidth").unwrap_or(0);
    let expected_width = option_count.checked_mul(BALLOT_PRIVACY_ENCODED_COORDINATES_PER_OPTION);
    let package_references = array_field(statement, "packageReferences");

    if string_field(statement, "objectType") != Some("AggregateDerivationStatement")
        || u64_object_field(statement, "objectVersion") != Some(1)
        || statement_digest.is_none()
        || expected_statement_digest.as_deref() != statement_digest
        || string_field(statement, "proofProfileId") != Some("aggregate-derivation-linear-proof-v1")
        || string_field(statement, "proofParameterProfileId")
            != Some(AGGREGATE_DERIVATION_PARAMETER_PROFILE_ID)
        || string_field(statement, "proofEncodingProfileId")
            != Some(AGGREGATE_DERIVATION_PROOF_ENCODING_PROFILE_ID)
        || option_count < BALLOT_PRIVACY_MINIMUM_OPTION_COUNT as u64
        || option_count > BALLOT_PRIVACY_MAXIMUM_OPTION_COUNT as u64
        || expected_width.and_then(|width| usize::try_from(width).ok()) != Some(share_vector_width)
        || !(BALLOT_PRIVACY_MINIMUM_UNSAFE_PARTICIPANT_COUNT
            ..=BALLOT_PRIVACY_MAXIMUM_PARTICIPANT_COUNT)
            .contains(&participant_count)
        || package_references.is_none_or(|references| !package_references_are_canonical(references))
        || !small_roster_acknowledgement_matches_policy
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation statement digest, profile, or dimension policy is invalid.",
            object_digest,
        ));
    }
    refused_objects
}

fn package_references_are_canonical(package_references: &[Value]) -> bool {
    let mut seen_package_digests = BTreeSet::new();
    let mut previous_package_digest: Option<&str> = None;

    for package_reference in package_references {
        let Some(package_digest) = string_field(package_reference, "ballotPackageDigest") else {
            return false;
        };
        if previous_package_digest.is_some_and(|previous| previous > package_digest) {
            return false;
        }
        if !seen_package_digests.insert(package_digest) {
            return false;
        }
        previous_package_digest = Some(package_digest);
    }

    true
}

fn collect_aggregate_commitment_refusals(
    aggregate_commitment: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let commitment_digest = string_field(aggregate_commitment, "aggregateShareCommitmentDigest");
    let expected_commitment_digest =
        value_without_field(aggregate_commitment, "aggregateShareCommitmentDigest").and_then(
            |commitment_payload| {
                derive_digest("AggregateShareCommitmentDigest", &commitment_payload)
            },
        );
    let commitment_polynomial_vector =
        array_field(aggregate_commitment, "commitmentPolynomialVector");
    let vector_shape_is_valid = commitment_polynomial_vector.is_some_and(|vector| {
        vector.len() == SHARE_COMMITMENT_MODULE_RANK
            && vector.iter().all(|polynomial| {
                polynomial.as_array().is_some_and(|coefficients| {
                    coefficients.len() == SHARE_COMMITMENT_MODULE_DEGREE
                        && coefficients.iter().all(|coefficient| {
                            integer_value(coefficient)
                                .is_some_and(|coefficient| coefficient < SHARE_COMMITMENT_MODULUS)
                        })
                })
            })
    });

    if string_field(aggregate_commitment, "objectType") != Some("AggregateShareCommitment")
        || u64_object_field(aggregate_commitment, "objectVersion") != Some(1)
        || commitment_digest.is_none()
        || expected_commitment_digest.as_deref() != commitment_digest
        || commitment_digest != string_field(statement, "aggregateShareCommitmentDigest")
        || string_field(aggregate_commitment, "ballotSetDigest")
            != string_field(statement, "ballotSetDigest")
        || string_field(aggregate_commitment, "ceremonyId") != string_field(statement, "ceremonyId")
        || string_field(aggregate_commitment, "manifestDigest")
            != string_field(statement, "manifestDigest")
        || string_field(aggregate_commitment, "rosterDigest")
            != string_field(statement, "rosterDigest")
        || string_field(aggregate_commitment, "pollSpecDigest")
            != string_field(statement, "pollSpecDigest")
        || string_field(aggregate_commitment, "contributorIdentity")
            != string_field(statement, "contributorIdentity")
        || usize_object_field(aggregate_commitment, "contributorRosterPosition")
            != usize_object_field(statement, "contributorRosterPosition")
        || string_field(aggregate_commitment, "shareCommitmentProfileDigest")
            != string_field(statement, "shareCommitmentProfileDigest")
        || usize_object_field(aggregate_commitment, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || !vector_shape_is_valid
    {
        refused_objects.push(structural_refusal(
            "Aggregate share commitment digest, context, or polynomial shape is invalid.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_aggregate_certificate_refusals(
    certificate: &Value,
    statement: &Value,
    object_digest: Option<&str>,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    let certificate_digest = string_field(certificate, "shareCommitmentMessageBoundCertDigest");
    let expected_certificate_digest =
        value_without_field(certificate, "shareCommitmentMessageBoundCertDigest").and_then(
            |certificate_payload| {
                derive_digest(
                    "ShareCommitmentMessageBoundCertDigest",
                    &certificate_payload,
                )
            },
        );
    let maximum_canonical_turnout = u64_object_field(certificate, "maximumCanonicalTurnout");
    let maximum_aggregate_integer = u64_object_field(certificate, "maximumAggregateInteger");
    let opening_single_bound = u64_object_field(certificate, "openingRandomnessSingleBound");
    let opening_aggregate_bound = u64_object_field(certificate, "openingRandomnessAggregateBound");
    let quotient_bound = u64_object_field(certificate, "quotientBoundForAggregateReduction");
    let expected_maximum_aggregate_integer = maximum_canonical_turnout
        .and_then(|turnout| turnout.checked_mul(BALLOT_PRIVACY_FIELD_MODULUS - 1));
    let expected_opening_aggregate_bound = maximum_canonical_turnout
        .zip(opening_single_bound)
        .and_then(|(turnout, bound)| turnout.checked_mul(bound));
    let commitment_message_bound_allows_no_wrap =
        string_field(certificate, "commitmentMessageBound")
            .and_then(|bound| bound.parse::<u128>().ok())
            .zip(maximum_aggregate_integer.map(u128::from))
            .is_some_and(|(bound, maximum)| maximum < bound);
    let no_wrap_flags = certificate
        .get("noWraparoundCondition")
        .and_then(object_map);

    if string_field(certificate, "objectType") != Some("ShareCommitmentMessageBoundCert")
        || u64_object_field(certificate, "objectVersion") != Some(1)
        || certificate_digest.is_none()
        || expected_certificate_digest.as_deref() != certificate_digest
        || certificate_digest != string_field(statement, "shareCommitmentMessageBoundCertDigest")
        || string_field(certificate, "shareCommitmentProfileDigest")
            != string_field(statement, "shareCommitmentProfileDigest")
        || usize_object_field(certificate, "shareVectorWidth")
            != usize_object_field(statement, "shareVectorWidth")
        || maximum_canonical_turnout
            .zip(u64_object_field(statement, "canonicalTurnout"))
            .is_none_or(|(maximum_turnout, actual_turnout)| maximum_turnout < actual_turnout)
        || maximum_aggregate_integer != expected_maximum_aggregate_integer
        || opening_aggregate_bound != expected_opening_aggregate_bound
        || quotient_bound != maximum_canonical_turnout
        || !commitment_message_bound_allows_no_wrap
        || no_wrap_flags
            .and_then(|flags| flags.get("maximumAggregateIntegerLessThanCommitmentMessageBound"))
            .and_then(Value::as_bool)
            != Some(true)
        || no_wrap_flags
            .and_then(|flags| flags.get("openingRandomnessAggregateBoundMatchesTurnout"))
            .and_then(Value::as_bool)
            != Some(true)
    {
        refused_objects.push(structural_refusal(
            "Aggregate derivation no-wraparound certificate is invalid or permits wraparound.",
            object_digest,
        ));
    }

    refused_objects
}

fn collect_forbidden_witness_field_refusals(
    value: &Value,
    object_digest: Option<&str>,
    path: &str,
) -> Vec<Value> {
    let mut refused_objects = Vec::new();
    match value {
        Value::Array(array) => {
            for (item_index, item) in array.iter().enumerate() {
                refused_objects.extend(collect_forbidden_witness_field_refusals(
                    item,
                    object_digest,
                    &format!("{path}[{item_index}]"),
                ));
            }
        }
        Value::Object(object) => {
            for (field_name, field_value) in object {
                if forbidden_public_witness_field(field_name) {
                    refused_objects.push(structural_refusal(
                        format!(
                            "Aggregate derivation public component must not expose witness field {path}.{field_name}."
                        ),
                        object_digest,
                    ));
                } else {
                    refused_objects.extend(collect_forbidden_witness_field_refusals(
                        field_value,
                        object_digest,
                        &format!("{path}.{field_name}"),
                    ));
                }
            }
        }
        _ => {}
    }

    refused_objects
}

fn forbidden_public_witness_field(field_name: &str) -> bool {
    matches!(
        field_name,
        "aggregateIntegerShareVector"
            | "aggregateHistogram"
            | "aggregateOpeningRandomness"
            | "aggregateScore"
            | "aggregateScoreBits"
            | "aggregateShareVector"
            | "bridgeWitness"
            | "openingRandomness"
            | "plaintext"
            | "plaintextComparisonInputs"
            | "plaintextScoreBitInputs"
            | "proofWitness"
            | "quotient"
            | "rawAggregateWitness"
            | "receiverPlaintext"
            | "receiverSecretState"
            | "reducedFieldVector"
            | "secretState"
            | "sourceWitnessCoefficients"
            | "targetBasisDataPlaintext"
            | "tPvss"
            | "t_pvss"
            | "witness"
    )
}
