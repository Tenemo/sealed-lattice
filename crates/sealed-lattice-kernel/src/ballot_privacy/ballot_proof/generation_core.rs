use super::*;

pub(crate) struct BallotProofGenerationInput<'a> {
    linear_statement: &'a Value,
    parameter_set_value: &'a Value,
    proof_encoding_value: &'a Value,
    public_randomness_hex: &'a str,
    secret_state: &'a Value,
    prover_randomness_hex: &'a str,
}

impl<'a> BallotProofGenerationInput<'a> {
    pub(crate) fn from_required_fields(
        linear_statement: &'a Value,
        parameter_set_value: &'a Value,
        proof_encoding_value: &'a Value,
        public_randomness_hex: &'a str,
        secret_state: &'a Value,
        prover_randomness_hex: &'a str,
    ) -> Self {
        Self {
            linear_statement,
            parameter_set_value,
            proof_encoding_value,
            public_randomness_hex,
            secret_state,
            prover_randomness_hex,
        }
    }

    pub(crate) fn from_command_request(
        request: &'a Value,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            linear_statement: required_json_field(
                request,
                "linearStatement",
                "generateBallotProof",
            )?,
            parameter_set_value: required_json_field(
                request,
                "parameterSet",
                "generateBallotProof",
            )?,
            proof_encoding_value: required_json_field(
                request,
                "proofEncoding",
                "generateBallotProof",
            )?,
            public_randomness_hex: required_string_field(
                request,
                "publicRandomnessHex",
                "generateBallotProof",
            )?,
            secret_state: required_json_field(request, "secretState", "generateBallotProof")?,
            prover_randomness_hex: required_string_field(
                request,
                "proverRandomnessHex",
                "generateBallotProof",
            )?,
        })
    }
}

struct ParsedBallotProofGenerationInput<'a> {
    raw: BallotProofGenerationInput<'a>,
    parameter_set: LinearProofParameterSet,
    proof_encoding: LinearProofEncoding,
    statement_matrix_coefficients: Vec<Vec<Vec<u64>>>,
    target_vector_coefficients: Vec<Vec<u64>>,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    source_witness_coefficients: Vec<Vec<i64>>,
    public_randomness_array: [u8; 32],
    prover_randomness_array: [u8; 32],
}

impl<'a> ParsedBallotProofGenerationInput<'a> {
    fn parse(raw: BallotProofGenerationInput<'a>) -> crate::encoding::CanonicalResult<Self> {
        if string_field(raw.linear_statement, "projectionCoverage")
            != Some(FULL_BALLOT_PROOF_PROJECTION_COVERAGE)
        {
            return Err(invalid_preflight(
                "ballot proof generation requires a full encoded-score relation statement",
            ));
        }
        if string_field(raw.parameter_set_value, "profileId")
            != Some(FULL_BALLOT_PROOF_PARAMETER_PROFILE_ID)
        {
            return Err(invalid_preflight(
                "ballot proof generation requires the full-relation parameter profile",
            ));
        }
        if string_field(raw.proof_encoding_value, "profileId")
            != Some(FULL_BALLOT_PROOF_ENCODING_PROFILE_ID)
        {
            return Err(invalid_preflight(
                "ballot proof generation requires the full-relation proof encoding profile",
            ));
        }

        let parameter_set: LinearProofParameterSet =
            serde_json::from_value(raw.parameter_set_value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "parameterSet is malformed for ballot proof generation: {error}"
                ))
            })?;
        let proof_encoding: LinearProofEncoding =
            serde_json::from_value(raw.proof_encoding_value.clone()).map_err(|error| {
                invalid_preflight(format!(
                    "proofEncoding is malformed for ballot proof generation: {error}"
                ))
            })?;
        let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> = required_json_field(
            raw.linear_statement,
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
            raw.linear_statement,
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
                raw.linear_statement,
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
        let matrix_coefficient_representation = matrix_coefficient_representation_from_statement(
            raw.linear_statement,
            "linearStatement",
        )?;
        let source_witness_coefficients = source_witness_coefficients(raw.secret_state)?;
        let public_randomness_array =
            decode_32_byte_hex(raw.public_randomness_hex, "publicRandomnessHex")?;
        let prover_randomness_array =
            decode_32_byte_hex(raw.prover_randomness_hex, "proverRandomnessHex")?;

        Ok(Self {
            raw,
            parameter_set,
            proof_encoding,
            statement_matrix_coefficients,
            target_vector_coefficients,
            matrix_coefficient_representation,
            target_coefficient_representation,
            source_witness_coefficients,
            public_randomness_array,
            prover_randomness_array,
        })
    }
}

pub(crate) struct BallotComponentProofGenerationInput<'a> {
    component_id: &'a str,
    proof_input: &'a Value,
    secret_state: &'a Value,
    prover_randomness_hex: &'a str,
}

impl<'a> BallotComponentProofGenerationInput<'a> {
    pub(crate) fn from_required_fields(
        component_id: &'a str,
        proof_input: &'a Value,
        secret_state: &'a Value,
        prover_randomness_hex: &'a str,
    ) -> Self {
        Self {
            component_id,
            proof_input,
            secret_state,
            prover_randomness_hex,
        }
    }

    pub(crate) fn from_command_request(
        request: &'a Value,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            component_id: required_string_field(
                request,
                "componentId",
                "generateBallotComponentProof",
            )?,
            proof_input: required_json_field(
                request,
                "proofInput",
                "generateBallotComponentProof",
            )?,
            secret_state: required_json_field(
                request,
                "secretState",
                "generateBallotComponentProof",
            )?,
            prover_randomness_hex: required_string_field(
                request,
                "proverRandomnessHex",
                "generateBallotComponentProof",
            )?,
        })
    }
}

pub(crate) fn generate_ballot_proof(input: BallotProofGenerationInput<'_>) -> Value {
    match generate_ballot_proof_inner(input) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateBallotProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_ballot_proof_from_command_request(request: &Value) -> Value {
    match BallotProofGenerationInput::from_command_request(request) {
        Ok(input) => generate_ballot_proof(input),
        Err(error) => structural_rejection("generateBallotProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_ballot_proof_inner(
    input: BallotProofGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let input = ParsedBallotProofGenerationInput::parse(input)?;

    let generation = generate_linear_proof(LinearProverProofInput {
        parameter_set: &input.parameter_set,
        proof_encoding: &input.proof_encoding,
        statement_matrix_coefficients: &input.statement_matrix_coefficients,
        target_vector_coefficients: &input.target_vector_coefficients,
        matrix_coefficient_representation: input.matrix_coefficient_representation,
        target_coefficient_representation: input.target_coefficient_representation,
        source_witness_coefficients: &input.source_witness_coefficients,
        public_randomness: &input.public_randomness_array,
        prover_randomness: &input.prover_randomness_array,
    })?;
    let proof_hex = crate::hashing::to_hex(&generation.proof_bytes);
    let vector_case = json!({
        "caseName": "generated-ballot-proof",
        "description": "Ballot linear proof generated by the internal Rust prover.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": input.raw.parameter_set_value,
        "proofEncoding": input.raw.proof_encoding_value,
        "publicRandomnessHex": input.raw.public_randomness_hex,
        "statementMatrixCoefficients": input.statement_matrix_coefficients,
        "targetVectorCoefficients": input.target_vector_coefficients,
        "matrixCoefficientRepresentation": input.matrix_coefficient_representation,
        "targetCoefficientRepresentation": input.target_coefficient_representation,
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

pub(crate) fn generate_ballot_component_proof(
    input: BallotComponentProofGenerationInput<'_>,
) -> Value {
    match generate_ballot_component_proof_inner(input) {
        Ok(value) => value,
        Err(error) => {
            structural_rejection("generateBallotComponentProof", vec![error.to_json_value()])
        }
    }
}

pub(crate) fn generate_ballot_component_proof_from_command_request(request: &Value) -> Value {
    match BallotComponentProofGenerationInput::from_command_request(request) {
        Ok(input) => generate_ballot_component_proof(input),
        Err(error) => {
            structural_rejection("generateBallotComponentProof", vec![error.to_json_value()])
        }
    }
}

pub(crate) fn generate_ballot_component_proof_inner(
    input: BallotComponentProofGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let component_id = input.component_id;
    let proof_input = input.proof_input;
    let secret_state = input.secret_state;
    let prover_randomness_hex = input.prover_randomness_hex;
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
    if proof_statement_format == PUBLIC_BINDING_CHECK_PROOF_STATEMENT_FORMAT {
        if component_id != "receiver-key-binding-component" {
            return Err(invalid_preflight(
                "public binding check proof generation is only valid for the receiver-key binding component",
            ));
        }
        return Ok(json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "generateBallotComponentProof",
            "componentId": component_id,
            "statusLabels": [
                "BallotComponentPublicBindingCheckProofBytesGenerated"
            ],
            "acceptedHashes": [],
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
    generation: &'a linear_proof::prover::LinearProverProofGeneration,
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
    generation: &'a linear_proof::prover::LinearProverProofGeneration,
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
    summary: linear_proof::prover::LinearProverProofSummary,
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
        "acceptedHashes": [],
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
