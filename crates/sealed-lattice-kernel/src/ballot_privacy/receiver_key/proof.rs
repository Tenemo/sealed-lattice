use super::*;

pub(crate) fn verify_receiver_key_linear_proof_bytes(
    receiver_key_proof: &Value,
    linear_statement: &Value,
    proof_bytes_hex: &str,
    public_randomness_hex: &str,
    parameter_set: &Value,
    proof_encoding: &Value,
) -> Value {
    let mut refused_objects = Vec::new();
    let receiver_key_proof_root = string_field(receiver_key_proof, "receiverKeyProofRoot");
    let linear_statement_hash = string_field(linear_statement, "statementHash");
    let expected_proof_encoding_hash =
        derive_receiver_key_proof_encoding_profile_hash(proof_encoding);
    let expected_parameter_set_hash = derive_receiver_key_proof_parameter_set_hash(parameter_set);
    let expected_public_randomness_hash =
        derive_receiver_key_public_randomness_hash(public_randomness_hex);
    let expected_linear_statement_hash =
        derive_receiver_key_linear_statement_hash(linear_statement);
    refused_objects.extend(collect_linear_proof_binding_refusals(
        LinearProofBindingValidationInput {
            proof_record: receiver_key_proof,
            linear_statement,
            parameter_set,
            proof_encoding,
            expected_linear_statement_hash,
            expected_parameter_set_hash,
            expected_proof_encoding_hash,
            expected_public_randomness_hash,
            object_hash: receiver_key_proof_root,
            parameter_profile_requirement: Some(LinearProofProfileRequirement {
                profile_id: RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID,
                refusal_message:
                    "Receiver key proof records require the production receiver-key parameter profile.",
            }),
            proof_encoding_profile_requirement: Some(LinearProofProfileRequirement {
                profile_id: RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID,
                refusal_message:
                    "Receiver key proof records require the production receiver-key proof encoding profile.",
            }),
            messages: LinearProofBindingValidationMessages {
                canonical_statement_hash_mismatch:
                    "Receiver key linear statement hash does not match its canonical payload.",
                proof_record_statement_mismatch:
                    "Receiver key proof record is not bound to the supplied linear statement.",
                proof_encoding_hash_mismatch:
                    "Receiver key proof record is not bound to the supplied proof encoding profile.",
                parameter_set_hash_mismatch:
                    "Receiver key proof record is not bound to the supplied proof parameter set.",
                public_randomness_hash_mismatch:
                    "Receiver key proof record is not bound to the supplied public randomness.",
                parameter_set_size_mismatch:
                    "Receiver key proof parameter set is not bound to the proof record byte length.",
                parameter_set_malformed_prefix: "Receiver key proof parameter set is malformed",
                proof_encoding_size_mismatch:
                    "Receiver key proof encoding is not bound to the proof record byte length.",
                proof_encoding_malformed_prefix: "Receiver key proof encoding is malformed",
            },
        }
    ));
    if !refused_objects.is_empty() {
        return structural_rejection("verifyReceiverKeyProof", refused_objects);
    }

    let vector_case = json!({
        "caseName": "receiver-key-proof-record",
        "description": "Receiver-key proof record verification through the internal linear proof backend.",
        "mutation": "none",
        "expectedOutcome": "accept",
        "upstreamVectorAvailable": true,
        "parameterSet": parameter_set,
        "proofEncoding": proof_encoding,
        "publicRandomnessHex": public_randomness_hex,
        "statementMatrixCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("statementMatrixCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetVectorCoefficients": object_map(linear_statement)
            .and_then(|object| object.get("targetVectorCoefficients"))
            .cloned()
            .unwrap_or(Value::Null),
        "targetCoefficientRepresentation": object_map(linear_statement)
            .and_then(|object| object.get("targetCoefficientRepresentation"))
            .cloned()
            .unwrap_or(Value::Null),
        "proofHex": proof_bytes_hex,
        "expectedProofSizeBytes": object_map(receiver_key_proof)
            .and_then(|object| object.get("proofSizeBytes"))
            .cloned()
            .unwrap_or(Value::Null)
    });
    let proof_verification =
        linear_proof_verifier::verify_linear_proof_vector_case_value(&vector_case);
    if proof_verification
        .as_object()
        .and_then(|object| object.get("ok"))
        .and_then(Value::as_bool)
        != Some(true)
    {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "operation": "verifyReceiverKeyProof",
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": proof_verification
                .as_object()
                .and_then(|object| object.get("refusedObjects"))
                .cloned()
                .unwrap_or_else(|| json!([
                    {
                        "code": "InvalidFixture",
                        "message": "Receiver key proof backend verification failed without a structured refusal."
                    }
                ])),
            "unresolvedReason": proof_verification
                .as_object()
                .and_then(|object| object.get("unresolvedReason"))
                .cloned()
                .unwrap_or_else(|| json!("InvalidFixture"))
        });
    }

    let mut status_labels = vec![
        json!("ReceiverKeyProofRootRecomputed"),
        json!("ReceiverKeyProofBytesHashChecked"),
        json!("ReceiverKeyLinearStatementBound"),
        json!("ReceiverKeyLinearProofVerified"),
    ];
    if let Some(proof_status_labels) = proof_verification
        .as_object()
        .and_then(|object| object.get("statusLabels"))
        .and_then(Value::as_array)
    {
        status_labels.extend(proof_status_labels.iter().cloned());
    }
    let accepted_hashes = [
        receiver_key_proof_root,
        string_field(receiver_key_proof, "proofBytesHash"),
        string_field(receiver_key_proof, "proofParameterSetHash"),
        linear_statement_hash,
    ]
    .into_iter()
    .flatten()
    .map(Value::from)
    .collect::<Vec<_>>();

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "verifyReceiverKeyProof",
        "statusLabels": status_labels,
        "acceptedHashes": accepted_hashes,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub(crate) struct ReceiverKeyProofVerificationInput<'a> {
    receiver_key_proof: &'a Value,
    linear_proof_context: Option<ReceiverKeyLinearProofVerificationInput<'a>>,
}

struct ReceiverKeyLinearProofVerificationInput<'a> {
    linear_statement: &'a Value,
    proof_bytes_hex: &'a str,
    public_randomness_hex: &'a str,
    parameter_set: &'a Value,
    proof_encoding: &'a Value,
}

impl<'a> ReceiverKeyProofVerificationInput<'a> {
    fn from_command_request(request: &'a Value) -> Result<Self, Value> {
        let receiver_key_proof =
            required_json_field(request, "receiverKeyProof", "verifyReceiverKeyProof").map_err(
                |error| structural_rejection("verifyReceiverKeyProof", vec![error.to_json_value()]),
            )?;
        let proof_bytes_hex = string_field(request, "proofBytesHex");
        let refused_objects =
            collect_receiver_key_proof_refusals(receiver_key_proof, proof_bytes_hex);
        if !refused_objects.is_empty() {
            return Err(structural_rejection(
                "verifyReceiverKeyProof",
                refused_objects,
            ));
        }

        let linear_proof_context = match (
            object_map(request).and_then(|object| object.get("linearStatement")),
            proof_bytes_hex,
            string_field(request, "publicRandomnessHex"),
            object_map(request).and_then(|object| object.get("parameterSet")),
            object_map(request).and_then(|object| object.get("proofEncoding")),
        ) {
            (None, None, None, None, None) => None,
            (
                Some(linear_statement),
                Some(proof_bytes_hex),
                Some(public_randomness_hex),
                Some(parameter_set),
                Some(proof_encoding),
            ) => Some(ReceiverKeyLinearProofVerificationInput {
                linear_statement,
                proof_bytes_hex,
                public_randomness_hex,
                parameter_set,
                proof_encoding,
            }),
            _ => {
                return Err(structural_rejection(
                    "verifyReceiverKeyProof",
                    vec![structural_refusal(
                        "Receiver key proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement together.",
                        string_field(receiver_key_proof, "receiverKeyProofRoot"),
                    )],
                ));
            }
        };

        Ok(Self {
            receiver_key_proof,
            linear_proof_context,
        })
    }
}

pub(crate) fn verify_receiver_key_proof_from_command_request(request: &Value) -> Value {
    match ReceiverKeyProofVerificationInput::from_command_request(request) {
        Ok(input) => verify_receiver_key_proof(input),
        Err(rejection) => rejection,
    }
}

pub(crate) fn verify_receiver_key_proof(input: ReceiverKeyProofVerificationInput<'_>) -> Value {
    if let Some(linear_proof_context) = input.linear_proof_context {
        return verify_receiver_key_linear_proof_bytes(
            input.receiver_key_proof,
            linear_proof_context.linear_statement,
            linear_proof_context.proof_bytes_hex,
            linear_proof_context.public_randomness_hex,
            linear_proof_context.parameter_set,
            linear_proof_context.proof_encoding,
        );
    }

    structural_rejection(
        "verifyReceiverKeyProof",
        vec![structural_refusal(
            "Receiver key proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement.",
            string_field(input.receiver_key_proof, "receiverKeyProofRoot"),
        )],
    )
}

pub(crate) struct ReceiverKeyProofPreparationInput<'a> {
    linear_statement: &'a Value,
    parameter_set_value: &'a Value,
    proof_encoding_value: &'a Value,
    public_randomness_hex: &'a str,
    secret_state: &'a Value,
    prover_randomness_hex: Option<&'a str>,
}

impl<'a> ReceiverKeyProofPreparationInput<'a> {
    pub(crate) fn from_command_request(
        request: &'a Value,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            linear_statement: required_json_field(
                request,
                "linearStatement",
                "prepareReceiverKeyProofGeneration",
            )?,
            parameter_set_value: required_json_field(
                request,
                "parameterSet",
                "prepareReceiverKeyProofGeneration",
            )?,
            proof_encoding_value: required_json_field(
                request,
                "proofEncoding",
                "prepareReceiverKeyProofGeneration",
            )?,
            public_randomness_hex: required_string_field(
                request,
                "publicRandomnessHex",
                "prepareReceiverKeyProofGeneration",
            )?,
            secret_state: required_json_field(
                request,
                "secretState",
                "prepareReceiverKeyProofGeneration",
            )?,
            prover_randomness_hex: string_field(request, "proverRandomnessHex"),
        })
    }
}

pub(crate) fn prepare_receiver_key_proof_generation(
    input: ReceiverKeyProofPreparationInput<'_>,
) -> Value {
    match prepare_receiver_key_proof_generation_inner(input) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "prepareReceiverKeyProofGeneration",
            vec![error.to_json_value()],
        ),
    }
}

pub(crate) fn prepare_receiver_key_proof_generation_from_command_request(request: &Value) -> Value {
    match ReceiverKeyProofPreparationInput::from_command_request(request) {
        Ok(input) => prepare_receiver_key_proof_generation(input),
        Err(error) => structural_rejection(
            "prepareReceiverKeyProofGeneration",
            vec![error.to_json_value()],
        ),
    }
}

pub(crate) fn prepare_receiver_key_proof_generation_inner(
    input: ReceiverKeyProofPreparationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = input.linear_statement;
    let parameter_set_value = input.parameter_set_value;
    let proof_encoding_value = input.proof_encoding_value;
    let public_randomness_hex = input.public_randomness_hex;
    let secret_state = input.secret_state;
    let prover_randomness_hex = input.prover_randomness_hex;
    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for receiver-key proof preparation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for receiver-key proof preparation: {error}"
            ))
        })?;
    if parameter_set.profile_id != RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID {
        return Err(invalid_preflight(
            "receiver-key proof preparation requires the production receiver-key parameter profile",
        ));
    }
    if proof_encoding.profile_id != RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID {
        return Err(invalid_preflight(
            "receiver-key proof preparation requires the production receiver-key proof encoding profile",
        ));
    }
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
    let source_witness_coefficients = receiver_key_source_witness_coefficients(secret_state)?;
    let public_randomness = decode_hex(public_randomness_hex)?;
    if public_randomness.len() != 32 {
        return Err(invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
        ));
    }
    let public_randomness_array: [u8; 32] = public_randomness
        .as_slice()
        .try_into()
        .map_err(|_| {
            invalid_preflight(
                "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
            )
        })?;

    let preparation = prepare_linear_prover_witness(LinearProverWitnessInput {
        parameter_set: &parameter_set,
        proof_encoding: &proof_encoding,
        statement_matrix_coefficients: &statement_matrix_coefficients,
        target_vector_coefficients: &target_vector_coefficients,
        matrix_coefficient_representation,
        target_coefficient_representation,
        source_witness_coefficients: &source_witness_coefficients,
        public_randomness: &public_randomness,
    })?;
    let summary = preparation.summary();
    let commitment_preparation = match prover_randomness_hex {
        Some(prover_randomness_hex) => {
            let prover_randomness = decode_hex(prover_randomness_hex)?;
            if prover_randomness.len() != 32 {
                return Err(invalid_preflight(
                    "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
                ));
            }
            let prover_randomness_array: [u8; 32] = prover_randomness
                .as_slice()
                .try_into()
                .map_err(|_| {
                    invalid_preflight(
                        "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof preparation",
                    )
                })?;
            let statement_transcript =
                derive_linear_statement_transcript_with_matrix_coefficient_representation(
                    &parameter_set,
                    &proof_encoding,
                    &statement_matrix_coefficients,
                    &target_vector_coefficients,
                    matrix_coefficient_representation,
                    target_coefficient_representation,
                    &public_randomness,
                )?;
            Some(prepare_linear_prover_commitment(
                LinearProverCommitmentInput {
                    proof_encoding: &proof_encoding,
                    public_randomness: &public_randomness_array,
                    statement_transcript_hash: &statement_transcript
                        .public_parameters_and_statement_hash,
                    witness_preparation: &preparation,
                    prover_randomness: &prover_randomness_array,
                },
            )?)
        }
        None => None,
    };
    let accepted_hashes = [
        derive_receiver_key_linear_statement_hash(linear_statement),
        derive_receiver_key_proof_parameter_set_hash(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_hash(proof_encoding_value),
        derive_receiver_key_public_randomness_hash(public_randomness_hex),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();
    let mut status_labels = vec![
        "ReceiverKeySourceWitnessChecked",
        "ReceiverKeyProofRingWitnessPrepared",
        "ReceiverKeyNormSlackPrepared",
    ];
    if commitment_preparation.is_some() {
        status_labels.push("ReceiverKeyAbdlopCommitmentPrepared");
    }
    let commitment_summary = commitment_preparation.as_ref().map(|commitment| {
        let summary = commitment.summary();
        json!({
            "compressedCommitmentPolynomialCount": commitment.compressed_commitment_polynomial_count(),
            "openingRandomnessPolynomialCount": summary.opening_randomness_polynomial_count,
            "openingRemainderPolynomialCount": summary.opening_remainder_polynomial_count,
            "proverRandomnessSeedBytes": summary.prover_randomness_seed_bytes,
            "subprotocolSeedBytes": summary.subprotocol_seed_bytes,
            "abdlopCommitmentHash": summary.abdlop_commitment_hash_hex
        })
    });

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "prepareReceiverKeyProofGeneration",
        "statusLabels": status_labels,
        "acceptedHashes": accepted_hashes,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": false,
        "summary": {
            "relationWitnessPolynomialCount": summary.relation_witness_polynomial_count,
            "shortWitnessPolynomialCount": summary.short_witness_polynomial_count,
            "preparedShortWitnessPolynomialCount": preparation.short_witness_polynomial_count(),
            "witnessL2Squared": summary.witness_l2_squared.to_string(),
            "witnessL2BoundSquared": summary.witness_l2_bound_squared.to_string(),
            "normSlack": summary.norm_slack.to_string(),
            "abdlopCommitment": commitment_summary
        }
    }))
}

pub(crate) struct ReceiverKeyProofGenerationInput<'a> {
    linear_statement: &'a Value,
    parameter_set_value: &'a Value,
    proof_encoding_value: &'a Value,
    public_randomness_hex: &'a str,
    secret_state: &'a Value,
    prover_randomness_hex: &'a str,
}

impl<'a> ReceiverKeyProofGenerationInput<'a> {
    pub(crate) fn from_command_request(
        request: &'a Value,
    ) -> crate::encoding::CanonicalResult<Self> {
        Ok(Self {
            linear_statement: required_json_field(
                request,
                "linearStatement",
                "generateReceiverKeyProof",
            )?,
            parameter_set_value: required_json_field(
                request,
                "parameterSet",
                "generateReceiverKeyProof",
            )?,
            proof_encoding_value: required_json_field(
                request,
                "proofEncoding",
                "generateReceiverKeyProof",
            )?,
            public_randomness_hex: required_string_field(
                request,
                "publicRandomnessHex",
                "generateReceiverKeyProof",
            )?,
            secret_state: required_json_field(request, "secretState", "generateReceiverKeyProof")?,
            prover_randomness_hex: required_string_field(
                request,
                "proverRandomnessHex",
                "generateReceiverKeyProof",
            )?,
        })
    }
}

pub(crate) fn generate_receiver_key_proof(input: ReceiverKeyProofGenerationInput<'_>) -> Value {
    match generate_receiver_key_proof_inner(input) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateReceiverKeyProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_receiver_key_proof_from_command_request(request: &Value) -> Value {
    match ReceiverKeyProofGenerationInput::from_command_request(request) {
        Ok(input) => generate_receiver_key_proof(input),
        Err(error) => structural_rejection("generateReceiverKeyProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_receiver_key_proof_inner(
    input: ReceiverKeyProofGenerationInput<'_>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = input.linear_statement;
    let parameter_set_value = input.parameter_set_value;
    let proof_encoding_value = input.proof_encoding_value;
    let public_randomness_hex = input.public_randomness_hex;
    let secret_state = input.secret_state;
    let prover_randomness_hex = input.prover_randomness_hex;

    let parameter_set: LinearProofParameterSet =
        serde_json::from_value(parameter_set_value.clone()).map_err(|error| {
            invalid_preflight(format!(
                "parameterSet is malformed for receiver-key proof generation: {error}"
            ))
        })?;
    let proof_encoding: LinearProofEncoding = serde_json::from_value(proof_encoding_value.clone())
        .map_err(|error| {
            invalid_preflight(format!(
                "proofEncoding is malformed for receiver-key proof generation: {error}"
            ))
        })?;
    if parameter_set.profile_id != RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID {
        return Err(invalid_preflight(
            "receiver-key proof generation requires the production receiver-key parameter profile",
        ));
    }
    if proof_encoding.profile_id != RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID {
        return Err(invalid_preflight(
            "receiver-key proof generation requires the production receiver-key proof encoding profile",
        ));
    }
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
    let source_witness_coefficients = receiver_key_source_witness_coefficients(secret_state)?;
    let public_randomness = decode_hex(public_randomness_hex)?;
    if public_randomness.len() != 32 {
        return Err(invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        ));
    }
    let public_randomness_array: [u8; 32] = public_randomness.as_slice().try_into().map_err(|_| {
        invalid_preflight(
            "publicRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        )
    })?;
    let prover_randomness = decode_hex(prover_randomness_hex)?;
    if prover_randomness.len() != 32 {
        return Err(invalid_preflight(
            "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        ));
    }
    let prover_randomness_array: [u8; 32] = prover_randomness.as_slice().try_into().map_err(|_| {
        invalid_preflight(
            "proverRandomnessHex must encode exactly 32 bytes for receiver-key proof generation",
        )
    })?;

    let generation = generate_receiver_key_linear_proof(LinearProverProofInput {
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
        "caseName": "generated-receiver-key-proof",
        "description": "Receiver-key linear proof generated by the internal Rust prover.",
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
            "generated receiver-key proof did not verify against its public statement",
        ));
    }
    let accepted_hashes = [
        derive_receiver_key_linear_statement_hash(linear_statement),
        derive_receiver_key_proof_parameter_set_hash(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_hash(proof_encoding_value),
        derive_receiver_key_public_randomness_hash(public_randomness_hex),
    ]
    .into_iter()
    .flatten()
    .collect::<Vec<_>>();

    Ok(json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "operation": "generateReceiverKeyProof",
        "statusLabels": [
            "ReceiverKeySourceWitnessChecked",
            "ReceiverKeyProofRingWitnessPrepared",
            "ReceiverKeyAbdlopCommitmentPrepared",
            "ReceiverKeyTboxResponsesGenerated",
            "ReceiverKeyQuadraticChallengeGenerated",
            "ReceiverKeyProofBytesGenerated",
            "ReceiverKeyProofGenerationVerified"
        ],
        "acceptedHashes": accepted_hashes,
        "refusedObjects": [],
        "unresolvedReason": Value::Null,
        "generatedProofBytes": true,
        "proofBytesHex": proof_hex,
        "proofSizeBytes": generation.summary.proof_size_bytes,
        "summary": {
            "abdlopCommitmentHash": generation.summary.abdlop_commitment_hash_hex,
            "z34ChallengeHash": generation.summary.z34_challenge_hash_hex,
            "generatorChallengeHash": generation.summary.generator_challenge_hash_hex,
            "quadraticChallengeHash": generation.summary.quadratic_challenge_hash_hex
        }
    }))
}
