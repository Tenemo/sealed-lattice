use super::*;

pub fn generate_ballot_proof(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_ballot_proof_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateBallotProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_ballot_proof_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for ballot proof generation")
    })?;
    if string_field(linear_statement, "projectionCoverage")
        != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires a full encoded-score relation statement",
        ));
    }
    let parameter_set_value = parameter_set
        .ok_or_else(|| invalid_preflight("parameterSet is required for ballot proof generation"))?;
    let proof_encoding_value = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for ballot proof generation")
    })?;
    if string_field(parameter_set_value, "profileId")
        != Some(FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires the full-relation parameter profile",
        ));
    }
    if string_field(proof_encoding_value, "profileId")
        != Some(FULL_BALLOT_PROOF_ENCODING_PROFILE_ID)
    {
        return Err(invalid_preflight(
            "ballot proof generation requires the full-relation proof encoding profile",
        ));
    }
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for ballot proof generation")
    })?;
    let secret_state = secret_state
        .ok_or_else(|| invalid_preflight("secretState is required for ballot proof generation"))?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for ballot proof generation")
    })?;

    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for ballot proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for ballot proof generation: {error}"
            ))
        })?;
    let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
        linear_statement,
        "statementMatrixCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.statementMatrixCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
        linear_statement,
        "targetVectorCoefficients",
        "linearStatement",
    )
    .and_then(|value| {
        serde_json::from_value(value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "linearStatement.targetVectorCoefficients is malformed: {error}"
            ))
        })
    })?;
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            linear_statement,
            "targetCoefficientRepresentation",
            "linearStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "linearStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let matrix_coefficient_representation =
        matrix_coefficient_representation_from_statement(linear_statement, "linearStatement")?;
    let source_witness_coefficients = source_witness_coefficients(secret_state)?;
    let public_randomness_array = decode_32_byte_hex(public_randomness_hex, "publicRandomnessHex")?;
    let prover_randomness_array = decode_32_byte_hex(prover_randomness_hex, "proverRandomnessHex")?;

    let generation = generate_linear_proof(LinearProverProofInput {
        parameter_set: &parameter_set,
        proof_encoding: &proof_encoding,
        statement_matrix_coefficients: &statement_matrix_coefficients,
        target_vector_coefficients: &target_vector_coefficients,
        matrix_coefficient_representation,
        target_coefficient_representation,
        source_witness_coefficients: &source_witness_coefficients,
        public_randomness: &public_randomness_array,
        prover_randomness: &prover_randomness_array,
    })?;
    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    let vector_case = json!({
        "caseName": "generated-ballot-proof",
        "description": "Ballot linear proof generated by the internal Rust prover.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set_value,
        "proofEncoding": proof_encoding_value,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": statement_matrix_coefficients,
        "targetVectorCoefficients": target_vector_coefficients,
        "matrixCoefficientRepresentation": matrix_coefficient_representation,
        "targetCoefficientRepresentation": target_coefficient_representation,
        "proofHex": proof_hex,
        "expectedProofSizeBytes": generation.summary.proof_size_bytes
    });
    let verification = linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated ballot proof did not verify against its public statement",
        ));
    }

    Ok(generated_proof_success(
        "generateBallotProof",
        "BallotGeneratedProofVerified",
        proof_hex,
        generation.summary,
    ))
}

pub fn generate_ballot_component_proof(
    component_id: Option<&str>,
    proof_input: Option<&Value>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_ballot_component_proof_inner(
        component_id,
        proof_input,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotComponentProof", vec![error.to_json_value()])
        }
    }
}

pub(crate) fn generate_ballot_component_proof_inner(
    component_id: Option<&str>,
    proof_input: Option<&Value>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let component_id = component_id.ok_or_else(|| {
        invalid_preflight("componentId is required for component proof generation")
    })?;
    let proof_input = proof_input.ok_or_else(|| {
        invalid_preflight("proofInput is required for component proof generation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for component proof generation")
    })?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for component proof generation")
    })?;
    if string_field(proof_input, "componentId") != Some(component_id) {
        return Err(invalid_preflight(
            "component proof input is not bound to the requested component",
        ));
    }

    let proof_statement_format =
        string_field(proof_input, "proofStatementFormat").ok_or_else(|| {
            invalid_preflight(
                "proofInput.proofStatementFormat is required for component proof generation",
            )
        })?;
    if proof_statement_format == PUBLIC_ZERO_PROOF_STATEMENT_FORMAT {
        if component_id != "receiver-key-binding-component" {
            return Err(invalid_preflight(
                "public-zero component proof generation is only valid for the receiver-key binding component",
            ));
        }
        return Ok(json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "generateBallotComponentProof",
            "componentId": component_id,
            "statusLabels": [
                "BallotComponentPublicZeroProofBytesGenerated"
            ],
            "acceptedDigests": [],
            "refusedObjects": [],
            "unresolvedReason": Value::Null,
            "generatedProofBytes": true,
            "proofBytesHex": "",
            "proofSizeBytes": 0
        }));
    }

    let proof_statement = required_json_field(proof_input, "proofStatement", "proofInput")?;
    let parameter_set_value = required_json_field(proof_input, "proofParameterSet", "proofInput")?;
    let proof_encoding_value = required_json_field(proof_input, "proofEncoding", "proofInput")?;
    let public_randomness_hex =
        string_field(proof_input, "publicRandomnessHex").ok_or_else(|| {
            invalid_preflight(
                "proofInput.publicRandomnessHex is required for component proof generation",
            )
        })?;
    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "proofInput.proofParameterSet is malformed for component proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofInput.proofEncoding is malformed for component proof generation: {error}"
            ))
        })?;
    if proof_statement_format == SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT
        && proof_encoding.short_response_vector_length
            > MAX_GENERIC_SPARSE_COMPONENT_SHORT_RESPONSE_VECTOR_LENGTH
    {
        return Err(invalid_preflight(
            "generic sparse component proof generation is refused for production-sized field statements; a structured field proof statement is required",
        ));
    }
    let target_coefficient_representation: LinearProofTargetCoefficientRepresentation =
        required_json_field(
            proof_statement,
            "targetCoefficientRepresentation",
            "proofInput.proofStatement",
        )
        .and_then(|value| {
            serde_json::from_value(value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "proofInput.proofStatement.targetCoefficientRepresentation is malformed: {error}"
                ))
            })
        })?;
    let matrix_coefficient_representation = matrix_coefficient_representation_from_statement(
        proof_statement,
        "proofInput.proofStatement",
    )?;
    let source_witness_coefficients = source_witness_coefficients(secret_state)?;
    let public_randomness_array =
        decode_32_byte_hex(public_randomness_hex, "proofInput.publicRandomnessHex")?;
    let prover_randomness_array = decode_32_byte_hex(prover_randomness_hex, "proverRandomnessHex")?;

    let generation = match proof_statement_format {
        DENSE_COMPONENT_PROOF_STATEMENT_FORMAT => {
            let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
                proof_statement,
                "statementMatrixCoefficients",
                "proofInput.proofStatement",
            )
            .and_then(|value| {
                serde_json::from_value(value.clone()).map_err(|error| {
                    invalid_preflight(format!(
                        "proofInput.proofStatement.statementMatrixCoefficients is malformed: {error}"
                    ))
                })
            })?;
            let target_vector_coefficients: Vec<Vec<u64>> = required_json_field(
                proof_statement,
                "targetVectorCoefficients",
                "proofInput.proofStatement",
            )
            .and_then(|value| {
                serde_json::from_value(value.clone()).map_err(|error| {
                    invalid_preflight(format!(
                        "proofInput.proofStatement.targetVectorCoefficients is malformed: {error}"
                    ))
                })
            })?;
            let generation = generate_linear_proof(LinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                statement_matrix_coefficients: &statement_matrix_coefficients,
                target_vector_coefficients: &target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
            let vector_case = json!({
                "caseName": format!("{component_id}-generated-component-proof"),
                "description": "Ballot component proof generated by the internal Rust prover.",
                "mutation": "none",
                "expectedOutcome": "accept",
                "upstreamVectorAvailable": true,
                "parameterSet": parameter_set_value,
                "proofEncoding": proof_encoding_value,
                "publicRandomnessHex": public_randomness_hex,
                "statementMatrixCoefficients": statement_matrix_coefficients,
                "targetVectorCoefficients": target_vector_coefficients,
                "matrixCoefficientRepresentation": matrix_coefficient_representation,
                "targetCoefficientRepresentation": target_coefficient_representation,
                "proofHex": proof_hex,
                "expectedProofSizeBytes": generation.summary.proof_size_bytes
            });
            let verification =
                linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
            if verification
                .as_object()
                .and_then(|object| object.get("ok"))
                .and_then(Value::as_bool)
                != Some(true)
            {
                return Err(invalid_preflight(
                    "generated dense component proof did not verify against its public statement",
                ));
            }

            generation
        }
        SPARSE_COMPONENT_PROOF_STATEMENT_FORMAT => {
            let parsed_sparse_statement =
                sparse_matrix_from_sparse_component_statement(proof_statement)
                    .map_err(|error| invalid_preflight(error.message))?;
            let generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            verify_generated_sparse_component_proof(GeneratedSparseComponentProofCheck {
                component_id,
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_sparse_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_sparse_statement.target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                generation: &generation,
            })?;

            generation
        }
        STRUCTURED_SHARE_COMMITMENT_PROOF_STATEMENT_FORMAT => {
            let parsed_structured_statement =
                parse_structured_share_commitment_statement(proof_statement)
                    .map_err(|error| invalid_preflight(error.message))?;
            let generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                source_statement_matrix: &parsed_structured_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_structured_statement.target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            verify_generated_sparse_component_proof(GeneratedSparseComponentProofCheck {
                component_id,
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                source_statement_matrix: &parsed_structured_statement.source_statement_matrix,
                target_vector_coefficients: &parsed_structured_statement.target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                generation: &generation,
            })?;

            generation
        }
        STRUCTURED_RECEIVER_ENCRYPTION_PROOF_STATEMENT_FORMAT => {
            let parsed_structured_statement =
                parse_structured_receiver_encryption_statement(proof_statement)
                    .map_err(|error| invalid_preflight(error.message))?;
            let generation = generate_streamed_linear_proof(StreamedLinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                statement: &parsed_structured_statement,
                matrix_coefficient_representation,
                target_coefficient_representation,
                source_witness_coefficients: &source_witness_coefficients,
                public_randomness: &public_randomness_array,
                prover_randomness: &prover_randomness_array,
            })?;
            verify_generated_streamed_component_proof(GeneratedStreamedComponentProofCheck {
                case_name: &format!("{component_id}-generated-component-proof"),
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex,
                statement: &parsed_structured_statement,
                matrix_coefficient_representation,
                target_coefficient_representation,
                generation: &generation,
            })?;

            generation
        }
        _ => {
            return Err(invalid_preflight(
                "component proof statement format is not supported for proof generation",
            ));
        }
    };

    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    Ok(generated_proof_success(
        "generateBallotComponentProof",
        "BallotComponentGeneratedProofVerified",
        proof_hex,
        generation.summary,
    ))
}

pub(crate) struct GeneratedSparseComponentProofCheck<'a> {
    component_id: &'a str,
    parameter_set: &'a LinearProofParameterSet,
    proof_encoding: &'a LinearProofEncoding,
    public_randomness_hex: &'a str,
    source_statement_matrix: &'a SparsePolynomialMatrix,
    target_vector_coefficients: &'a [Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    generation: &'a linear_proof_prover::LinearProverProofGeneration,
}

pub(crate) struct GeneratedStreamedComponentProofCheck<'a, Statement>
where
    Statement: StreamedLinearProofStatement,
{
    case_name: &'a str,
    parameter_set: &'a LinearProofParameterSet,
    proof_encoding: &'a LinearProofEncoding,
    public_randomness_hex: &'a str,
    statement: &'a Statement,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    generation: &'a linear_proof_prover::LinearProverProofGeneration,
}

pub(crate) fn verify_generated_sparse_component_proof(
    input: GeneratedSparseComponentProofCheck<'_>,
) -> crate::encoding::CanonicalResult<()> {
    let proof_hex = crate::hashing::to_hex(&input.generation.proof_bytes);
    let verification = linear_proof_verifier::verify_sparse_linear_proof_components(
        linear_proof_verifier::SparseLinearProofVerificationInput {
            case_name: &format!("{}-generated-component-proof", input.component_id),
            parameter_set: input.parameter_set,
            proof_encoding: input.proof_encoding,
            public_randomness_hex: input.public_randomness_hex,
            source_statement_matrix: input.source_statement_matrix,
            target_vector_coefficients: input.target_vector_coefficients,
            matrix_coefficient_representation: input.matrix_coefficient_representation,
            target_coefficient_representation: input.target_coefficient_representation,
            proof_hex: &proof_hex,
            expected_proof_size_bytes: Some(input.generation.summary.proof_size_bytes),
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated sparse component proof did not verify against its public statement",
        ));
    }

    Ok(())
}

pub(crate) fn verify_generated_streamed_component_proof<Statement>(
    input: GeneratedStreamedComponentProofCheck<'_, Statement>,
) -> crate::encoding::CanonicalResult<()>
where
    Statement: StreamedLinearProofStatement,
{
    let proof_hex = crate::hashing::to_hex(&input.generation.proof_bytes);
    let verification = linear_proof_verifier::verify_streamed_linear_proof_components(
        linear_proof_verifier::StreamedLinearProofVerificationInput {
            case_name: input.case_name,
            parameter_set: input.parameter_set,
            proof_encoding: input.proof_encoding,
            public_randomness_hex: input.public_randomness_hex,
            statement: input.statement,
            matrix_coefficient_representation: input.matrix_coefficient_representation,
            target_coefficient_representation: input.target_coefficient_representation,
            proof_hex: &proof_hex,
            expected_proof_size_bytes: Some(input.generation.summary.proof_size_bytes),
        },
    );
    if verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return Err(invalid_preflight(
            "generated streamed component proof did not verify against its public statement",
        ));
    }

    Ok(())
}

pub(crate) fn generated_proof_success(
    operation: &str,
    verified_status_label: &str,
    proof_hex: String,
    summary: linear_proof_prover::LinearProverProofSummary,
) -> Value {
    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": operation,
        "statusLabels": [
            "LinearProofSourceWitnessChecked",
            "LinearProofRingWitnessPrepared",
            "LinearProofAbdlopCommitmentPrepared",
            "LinearProofTboxResponsesGenerated",
            "LinearProofQuadraticChallengeGenerated",
            "LinearProofBytesGenerated",
            verified_status_label
        ],
        "acceptedDigests": [],
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_hex,
        "proofSizeBytes": summary.proof_size_bytes,
        "summary": {
            "abdlopCommitmentHash": summary.abdlop_commitment_hash_hex,
            "z34ChallengeHash": summary.z34_challenge_hash_hex,
            "generatorChallengeHash": summary.generator_challenge_hash_hex,
            "quadraticChallengeHash": summary.quadratic_challenge_hash_hex
        }
    })
}
