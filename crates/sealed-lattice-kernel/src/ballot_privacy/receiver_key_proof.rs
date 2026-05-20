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
    let linear_statement_digest = string_field(linear_statement, "statementDigest");
    let expected_proof_encoding_digest =
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding);
    let expected_parameter_set_digest =
        derive_receiver_key_proof_parameter_set_digest(parameter_set);
    let expected_public_randomness_digest =
        derive_receiver_key_public_randomness_digest(public_randomness_hex);
    let expected_linear_statement_digest =
        derive_receiver_key_linear_statement_digest(linear_statement);
    let proof_size_bytes = object_map(receiver_key_proof)
        .and_then(|object| object.get("proofSizeBytes"))
        .and_then(Value::as_u64)
        .and_then(|proof_size_bytes| usize::try_from(proof_size_bytes).ok());
    let supplied_parameter_profile_id = string_field(parameter_set, "profileId");
    let supplied_proof_encoding_profile_id = string_field(proof_encoding, "profileId");

    if linear_statement_digest != expected_linear_statement_digest.as_deref() {
        refused_objects.push(structural_refusal(
            "Receiver key linear statement digest does not match its canonical payload.",
            receiver_key_proof_root,
        ));
    }
    if supplied_parameter_profile_id != Some(RECEIVER_KEY_PROOF_PARAMETER_PROFILE_ID) {
        refused_objects.push(structural_refusal(
            "Receiver key proof records require the production receiver-key parameter profile.",
            receiver_key_proof_root,
        ));
    }
    if supplied_proof_encoding_profile_id != Some(RECEIVER_KEY_PROOF_ENCODING_PROFILE_ID) {
        refused_objects.push(structural_refusal(
            "Receiver key proof records require the production receiver-key proof encoding profile.",
            receiver_key_proof_root,
        ));
    }

    if string_field(receiver_key_proof, "linearStatementDigest") != linear_statement_digest {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied linear statement.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "proofEncodingProfileDigest")
        != expected_proof_encoding_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied proof encoding profile.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "proofParameterSetDigest")
        != expected_parameter_set_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied proof parameter set.",
            receiver_key_proof_root,
        ));
    }
    if string_field(receiver_key_proof, "publicRandomnessDigest")
        != expected_public_randomness_digest.as_deref()
    {
        refused_objects.push(structural_refusal(
            "Receiver key proof record is not bound to the supplied public randomness.",
            receiver_key_proof_root,
        ));
    }
    match serde_json::from_value::<LinearProofParameterSet>(parameter_set.clone()) {
        Ok(parameter_contract)
            if parameter_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Receiver key proof parameter set is not bound to the proof record byte length.",
                receiver_key_proof_root,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Receiver key proof parameter set is malformed: {error}"),
            receiver_key_proof_root,
        )),
    }
    match serde_json::from_value::<LinearProofEncoding>(proof_encoding.clone()) {
        Ok(proof_encoding_contract)
            if proof_encoding_contract.expected_proof_size_bytes != proof_size_bytes =>
        {
            refused_objects.push(structural_refusal(
                "Receiver key proof encoding is not bound to the proof record byte length.",
                receiver_key_proof_root,
            ));
        }
        Ok(_) => {}
        Err(error) => refused_objects.push(structural_refusal(
            format!("Receiver key proof encoding is malformed: {error}"),
            receiver_key_proof_root,
        )),
    }
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
            "acceptedDigests": [],
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
        json!("ReceiverKeyProofBytesDigestChecked"),
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
    let accepted_digests = [
        receiver_key_proof_root,
        string_field(receiver_key_proof, "proofBytesDigest"),
        string_field(receiver_key_proof, "proofParameterSetDigest"),
        linear_statement_digest,
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
        "acceptedDigests": accepted_digests,
        "refusedObjects": [],
        "unresolvedReason": Value::Null
    })
}

pub fn verify_receiver_key_proof(
    receiver_key_proof: &Value,
    linear_statement: Option<&Value>,
    proof_bytes_hex: Option<&str>,
    public_randomness_hex: Option<&str>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
) -> Value {
    let refused_objects = collect_receiver_key_proof_refusals(receiver_key_proof, proof_bytes_hex);
    if !refused_objects.is_empty() {
        return structural_rejection("verifyReceiverKeyProof", refused_objects);
    }

    match (
        linear_statement,
        proof_bytes_hex,
        public_randomness_hex,
        parameter_set,
        proof_encoding,
    ) {
        (None, None, None, None, None) => {}
        (
            Some(linear_statement),
            Some(proof_bytes_hex),
            Some(public_randomness_hex),
            Some(parameter_set),
            Some(proof_encoding),
        ) => {
            return verify_receiver_key_linear_proof_bytes(
                receiver_key_proof,
                linear_statement,
                proof_bytes_hex,
                public_randomness_hex,
                parameter_set,
                proof_encoding,
            );
        }
        _ => {
            return structural_rejection(
                "verifyReceiverKeyProof",
                vec![structural_refusal(
                    "Receiver key proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement together.",
                    string_field(receiver_key_proof, "receiverKeyProofRoot"),
                )],
            );
        }
    }

    structural_rejection(
        "verifyReceiverKeyProof",
        vec![structural_refusal(
            "Receiver key proof verification requires proof bytes, public randomness, proof parameters, proof encoding, and the public linear statement.",
            string_field(receiver_key_proof, "receiverKeyProofRoot"),
        )],
    )
}

pub fn prepare_receiver_key_proof_generation(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match prepare_receiver_key_proof_generation_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection(
            "prepareReceiverKeyProofGeneration",
            vec![error.to_json_value()],
        ),
    }
}

pub(crate) fn prepare_receiver_key_proof_generation_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for receiver-key proof preparation")
    })?;
    let parameter_set = parameter_set.ok_or_else(|| {
        invalid_preflight("parameterSet is required for receiver-key proof preparation")
    })?;
    let proof_encoding = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for receiver-key proof preparation")
    })?;
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for receiver-key proof preparation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for receiver-key proof preparation")
    })?;

    let parameter_set_value = parameter_set;
    let proof_encoding_value = proof_encoding;
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
    let accepted_digests = [
        derive_receiver_key_linear_statement_digest(linear_statement),
        derive_receiver_key_proof_parameter_set_digest(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding_value),
        derive_receiver_key_public_randomness_digest(public_randomness_hex),
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
        "acceptedDigests": accepted_digests,
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

pub fn generate_receiver_key_proof(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> Value {
    match generate_receiver_key_proof_inner(
        linear_statement,
        parameter_set,
        proof_encoding,
        public_randomness_hex,
        secret_state,
        prover_randomness_hex,
    ) {
        Ok(value) => value,
        Err(error) => structural_rejection("generateReceiverKeyProof", vec![error.to_json_value()]),
    }
}

pub(crate) fn generate_receiver_key_proof_inner(
    linear_statement: Option<&Value>,
    parameter_set: Option<&Value>,
    proof_encoding: Option<&Value>,
    public_randomness_hex: Option<&str>,
    secret_state: Option<&Value>,
    prover_randomness_hex: Option<&str>,
) -> crate::encoding::CanonicalResult<Value> {
    let linear_statement = linear_statement.ok_or_else(|| {
        invalid_preflight("linearStatement is required for receiver-key proof generation")
    })?;
    let parameter_set_value = parameter_set.ok_or_else(|| {
        invalid_preflight("parameterSet is required for receiver-key proof generation")
    })?;
    let proof_encoding_value = proof_encoding.ok_or_else(|| {
        invalid_preflight("proofEncoding is required for receiver-key proof generation")
    })?;
    let public_randomness_hex = public_randomness_hex.ok_or_else(|| {
        invalid_preflight("publicRandomnessHex is required for receiver-key proof generation")
    })?;
    let secret_state = secret_state.ok_or_else(|| {
        invalid_preflight("secretState is required for receiver-key proof generation")
    })?;
    let prover_randomness_hex = prover_randomness_hex.ok_or_else(|| {
        invalid_preflight("proverRandomnessHex is required for receiver-key proof generation")
    })?;

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
    let accepted_digests = [
        derive_receiver_key_linear_statement_digest(linear_statement),
        derive_receiver_key_proof_parameter_set_digest(parameter_set_value),
        derive_receiver_key_proof_encoding_profile_digest(proof_encoding_value),
        derive_receiver_key_public_randomness_digest(public_randomness_hex),
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
        "acceptedDigests": accepted_digests,
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
