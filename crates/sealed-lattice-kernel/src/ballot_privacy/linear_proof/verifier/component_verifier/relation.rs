use super::*;

pub(super) struct DecodedProofRelationVerificationInput<'a> {
    pub(super) parameter_set: &'a LinearProofParameterSet,
    pub(super) proof_encoding: &'a LinearProofEncoding,
    pub(super) statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    pub(super) target_vector_coefficients: &'a [Vec<u64>],
    pub(super) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(super) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(super) public_randomness: &'a [u8],
    pub(super) public_randomness_array: &'a [u8; 32],
    pub(super) decoded_proof: &'a DecodedLinearProof,
}

struct DecodedCanonicalLinearProof {
    decoded_proof: DecodedLinearProof,
}

struct AbdlopTboxVerificationInput<'a> {
    public_parameters_and_statement_hash: &'a [u8; 32],
    public_randomness_array: &'a [u8; 32],
    decoded_proof: &'a DecodedLinearProof,
    proof_encoding: &'a LinearProofEncoding,
}

pub(super) struct LinearProofTboxChallengeHashes {
    pub(super) z34_challenge_hash: [u8; 32],
    pub(super) generator_challenge_hash: [u8; 32],
}

pub(super) struct LinearProofRelationCoreInput<'a> {
    pub(super) public_parameters_and_statement_hash: &'a [u8; 32],
    pub(super) public_randomness_array: &'a [u8; 32],
    pub(super) decoded_proof: &'a DecodedLinearProof,
    pub(super) proof_encoding: &'a LinearProofEncoding,
}

struct QuadraticChallengeVerificationInput<'a> {
    tbox_accumulators: &'a TboxRelationAccumulatorSet,
    generator_challenge_hash: &'a [u8; 32],
    public_randomness_array: &'a [u8; 32],
    decoded_proof: &'a DecodedLinearProof,
    proof_encoding: &'a LinearProofEncoding,
}

fn decode_and_expand_public_randomness(
    public_randomness_hex: &str,
) -> CanonicalResult<(Vec<u8>, [u8; 32])> {
    let public_randomness = decode_hex(public_randomness_hex)?;
    if public_randomness.len() != 32 {
        return Err(invalid_vector(
            "publicRandomnessHex must encode exactly 32 bytes",
        ));
    }
    let public_randomness_array: [u8; 32] = public_randomness
        .as_slice()
        .try_into()
        .map_err(|_| invalid_vector("publicRandomnessHex must encode exactly 32 bytes"))?;
    derive_default_abdlop_public_parameters(&public_randomness_array)?;

    Ok((public_randomness, public_randomness_array))
}

fn decode_validated_canonical_linear_proof(
    proof_hex: &str,
    expected_proof_size_bytes: Option<usize>,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<DecodedCanonicalLinearProof> {
    let proof_bytes = LinearProofBytes::from_hex(proof_hex, expected_proof_size_bytes)?;
    let decoded_proof = decode_linear_proof(proof_bytes.bytes(), proof_encoding)?;
    let reencoded_proof = encode_linear_proof(&decoded_proof, proof_encoding)?;
    if reencoded_proof != proof_bytes.bytes() {
        return Err(invalid_vector(
            "decoded proof object does not re-encode to the original canonical bytes",
        ));
    }
    validate_norms(&decoded_proof, proof_encoding)?;

    Ok(DecodedCanonicalLinearProof { decoded_proof })
}

fn verify_abdlop_opening_and_tbox(
    input: AbdlopTboxVerificationInput<'_>,
) -> CanonicalResult<LinearProofTboxChallengeHashes> {
    let abdlop_commitment_hash = hash_abdlop_commitment(
        input.public_parameters_and_statement_hash,
        input.decoded_proof,
        input.proof_encoding,
    )?;
    validate_abdlop_linear_opening(
        &abdlop_commitment_hash,
        input.public_randomness_array,
        input.decoded_proof,
        input.proof_encoding,
    )?;
    let tbox_public_check_summary = validate_tbox_public_checks(
        &abdlop_commitment_hash,
        input.decoded_proof,
        input.proof_encoding,
    )?;

    Ok(LinearProofTboxChallengeHashes {
        z34_challenge_hash: challenge_hash_from_hex(&tbox_public_check_summary.z34_challenge_hash)?,
        generator_challenge_hash: challenge_hash_from_hex(
            &tbox_public_check_summary.generator_challenge_hash,
        )?,
    })
}

pub(super) fn verify_linear_proof_relation_core(
    input: LinearProofRelationCoreInput<'_>,
    apply_response_relations: impl FnOnce(
        &mut TboxRelationAccumulatorSet,
        &LinearProofTboxChallengeHashes,
    ) -> CanonicalResult<()>,
) -> CanonicalResult<()> {
    let tbox_challenge_hashes = verify_abdlop_opening_and_tbox(AbdlopTboxVerificationInput {
        public_parameters_and_statement_hash: input.public_parameters_and_statement_hash,
        public_randomness_array: input.public_randomness_array,
        decoded_proof: input.decoded_proof,
        proof_encoding: input.proof_encoding,
    })?;
    let mut tbox_accumulators = build_tbox_prefix_accumulators(
        &tbox_challenge_hashes.generator_challenge_hash,
        input.proof_encoding,
    )?;
    apply_response_relations(&mut tbox_accumulators, &tbox_challenge_hashes)?;
    validate_quadratic_challenge_from_tbox_accumulators(QuadraticChallengeVerificationInput {
        tbox_accumulators: &tbox_accumulators,
        generator_challenge_hash: &tbox_challenge_hashes.generator_challenge_hash,
        public_randomness_array: input.public_randomness_array,
        decoded_proof: input.decoded_proof,
        proof_encoding: input.proof_encoding,
    })
}

fn validate_quadratic_challenge_from_tbox_accumulators(
    input: QuadraticChallengeVerificationInput<'_>,
) -> CanonicalResult<()> {
    let many_quadratic_equations = build_many_quadratic_equations(
        input.tbox_accumulators,
        input.decoded_proof.hash_mask_vector(),
    )?;
    let folded_many_quadratic_equation = fold_many_quadratic_equations(
        &many_quadratic_equations,
        input.generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    validate_quadratic_challenge(
        input.generator_challenge_hash,
        input.public_randomness_array,
        input.decoded_proof,
        input.proof_encoding,
        &folded_many_quadratic_equation,
    )?;

    Ok(())
}

pub(super) fn compute_preflight_transcript_value(
    parameter_set: &LinearProofParameterSet,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    public_randomness: &[u8],
    proof_bytes: &[u8],
) -> CanonicalResult<Value> {
    let parameter_set_value = serde_json::to_value(parameter_set).map_err(|error| {
        invalid_vector(format!("parameter set could not be serialized: {error}"))
    })?;
    let statement_matrix_value =
        serde_json::to_value(statement_matrix_coefficients).map_err(|error| {
            invalid_vector(format!("statement matrix could not be serialized: {error}"))
        })?;
    let target_vector_value =
        serde_json::to_value(target_vector_coefficients).map_err(|error| {
            invalid_vector(format!("target vector could not be serialized: {error}"))
        })?;
    let transcript =
        compute_linear_proof_preflight_transcript(LinearProofPreflightTranscriptInput {
            parameter_set: &parameter_set_value,
            statement_matrix_coefficients: &statement_matrix_value,
            target_vector_coefficients: &target_vector_value,
            public_randomness,
            proof_bytes,
        })?;

    serde_json::to_value(transcript).map_err(|error| {
        invalid_vector(format!("preflight transcript could not serialize: {error}"))
    })
}

pub(super) fn challenge_hash_from_hex(hash_hex: &str) -> CanonicalResult<[u8; 32]> {
    let bytes = decode_hex(hash_hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_vector("challenge hash must encode exactly 32 bytes"))
}

pub(super) fn decode_statement_matrix(
    parameter_set: &LinearProofParameterSet,
    coefficients: &[Vec<Vec<u64>>],
) -> CanonicalResult<PolynomialMatrix> {
    if coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_vector(format!(
            "statementMatrixCoefficients must contain {} rows",
            parameter_set.statement_rows
        )));
    }

    let ring = PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    let mut entries =
        Vec::with_capacity(parameter_set.statement_rows * parameter_set.statement_columns);
    for row in coefficients {
        if row.len() != parameter_set.statement_columns {
            return Err(invalid_vector(format!(
                "each statementMatrixCoefficients row must contain {} columns",
                parameter_set.statement_columns
            )));
        }
        for polynomial_coefficients in row {
            entries.push(polynomial_coefficients.clone());
        }
    }

    PolynomialMatrix::new(
        ring,
        parameter_set.statement_rows,
        parameter_set.statement_columns,
        entries,
    )
}

pub(super) fn decode_target_vector(
    parameter_set: &LinearProofParameterSet,
    coefficients: &[Vec<u64>],
) -> CanonicalResult<PolynomialVector> {
    if coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_vector(format!(
            "targetVectorCoefficients must contain {} entries",
            parameter_set.statement_rows
        )));
    }

    let ring = PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    PolynomialVector::new(ring, coefficients.to_vec())
}

pub(crate) fn verify_sparse_linear_proof_components(
    input: SparseLinearProofVerificationInput<'_>,
) -> Value {
    match verify_sparse_linear_proof_components_inner(&input) {
        Ok(verified_status_labels) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": input.case_name,
            "vectorAvailable": true,
            "expectedOutcome": "accept",
            "statusLabels": verified_status_labels,
            "acceptedHashes": [],
            "refusedObjects": [],
            "unresolvedReason": null
        }),
        Err(error) => json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": input.case_name,
            "vectorAvailable": true,
            "expectedOutcome": "accept",
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": [
                {
                    "code": error.code.as_str(),
                    "message": error.message
                }
            ],
            "unresolvedReason": error.code.as_str()
        }),
    }
}

pub(crate) fn verify_streamed_linear_proof_components<Statement>(
    input: StreamedLinearProofVerificationInput<'_, Statement>,
) -> Value
where
    Statement: StreamedLinearProofStatement,
{
    match verify_streamed_linear_proof_components_inner(&input) {
        Ok(verified_status_labels) => json!({
            "ok": true,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": input.case_name,
            "vectorAvailable": true,
            "expectedOutcome": "accept",
            "statusLabels": verified_status_labels,
            "acceptedHashes": [],
            "refusedObjects": [],
            "unresolvedReason": null
        }),
        Err(error) => json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": input.case_name,
            "vectorAvailable": true,
            "expectedOutcome": "accept",
            "statusLabels": [],
            "acceptedHashes": [],
            "refusedObjects": [
                {
                    "code": error.code.as_str(),
                    "message": error.message
                }
            ],
            "unresolvedReason": error.code.as_str()
        }),
    }
}

pub(super) fn verify_sparse_linear_proof_components_inner(
    input: &SparseLinearProofVerificationInput<'_>,
) -> CanonicalResult<Value> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    let (public_randomness, public_randomness_array) =
        decode_and_expand_public_randomness(input.public_randomness_hex)?;
    let decoded_proof = decode_validated_canonical_linear_proof(
        input.proof_hex,
        input.expected_proof_size_bytes,
        input.proof_encoding,
    )?
    .decoded_proof;

    let transformed_statement_matrix =
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
            input.parameter_set,
            input.proof_encoding,
            input.source_statement_matrix,
            input.matrix_coefficient_representation,
        )?;
    let transformed_target_vector = transform_sparse_target_vector_to_proof_ring(
        input.parameter_set,
        input.proof_encoding,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
    )?;
    let statement_transcript =
        derive_dense_compatible_sparse_linear_statement_transcript_from_transformed(
            input.proof_encoding,
            &transformed_statement_matrix,
            &transformed_target_vector,
            &public_randomness,
        )?;
    verify_linear_proof_relation_core(
        LinearProofRelationCoreInput {
            public_parameters_and_statement_hash: &statement_transcript
                .public_parameters_and_statement_hash,
            public_randomness_array: &public_randomness_array,
            decoded_proof: &decoded_proof,
            proof_encoding: input.proof_encoding,
        },
        |tbox_accumulators, tbox_challenge_hashes| {
            apply_tbox_z4_response_relations_sparse(
                tbox_accumulators,
                &transformed_statement_matrix,
                &transformed_target_vector,
                decoded_proof.infinity_response_vector(),
                &tbox_challenge_hashes.z34_challenge_hash,
                input.proof_encoding,
            )?;
            apply_tbox_z3_response_relations_sparse(
                tbox_accumulators,
                &transformed_statement_matrix,
                decoded_proof.euclidean_response_vector(),
                &tbox_challenge_hashes.z34_challenge_hash,
                input.proof_encoding,
            )
        },
    )?;

    let mut status_labels = vec![
        "LinearProofCanonicalBytesVerified",
        "LinearProofNormBoundsChecked",
        "AbdlopPublicParametersExpanded",
        "AbdlopLinearOpeningRecovered",
        "TboxZ34ChallengeUpdated",
        "TboxGeneratorChallengeUpdated",
        "SparseLinearStatementStreamedAsDenseTranscript",
        "QuadraticAccumulatorHelpersChecked",
        "TboxRelationBuildersChecked",
        "TboxResponseRelationBuildersChecked",
        "ManyQuadraticEquationsFolded",
        "QuadraticChallengeRecomputed",
    ];
    status_labels.extend(linear_proof_claim_boundary_status_labels(
        input.proof_encoding,
    ));

    Ok(json!(status_labels))
}

pub(super) fn verify_streamed_linear_proof_components_inner<Statement>(
    input: &StreamedLinearProofVerificationInput<'_, Statement>,
) -> CanonicalResult<Value>
where
    Statement: StreamedLinearProofStatement,
{
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_streamed_statement_shape(input.parameter_set, input.proof_encoding, input.statement)?;
    let (public_randomness, public_randomness_array) =
        decode_and_expand_public_randomness(input.public_randomness_hex)?;
    let decoded_proof = decode_validated_canonical_linear_proof(
        input.proof_hex,
        input.expected_proof_size_bytes,
        input.proof_encoding,
    )?
    .decoded_proof;

    let source_polynomial_split_factor =
        source_polynomial_split_factor(input.parameter_set, input.proof_encoding)?;
    let transformed_statement_rows = input
        .parameter_set
        .statement_rows
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_vector("streamed transformed row count overflowed"))?;
    let transformed_statement_columns = input
        .parameter_set
        .statement_columns
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_vector("streamed transformed column count overflowed"))?;
    let statement_transcript = input.statement.derive_statement_transcript(
        input.parameter_set,
        input.proof_encoding,
        input.matrix_coefficient_representation,
        input.target_coefficient_representation,
        &public_randomness,
    )?;
    let transformed_target_vector = input.statement.transformed_target_vector(
        input.parameter_set,
        input.proof_encoding,
        input.target_coefficient_representation,
    )?;
    verify_linear_proof_relation_core(
        LinearProofRelationCoreInput {
            public_parameters_and_statement_hash: &statement_transcript
                .public_parameters_and_statement_hash,
            public_randomness_array: &public_randomness_array,
            decoded_proof: &decoded_proof,
            proof_encoding: input.proof_encoding,
        },
        |tbox_accumulators, tbox_challenge_hashes| {
            apply_tbox_z4_response_relations_with_product_builder(
                tbox_accumulators,
                TboxZ4ResponseRelationInputs {
                    transformed_statement_rows,
                    transformed_statement_columns,
                    transformed_target_vector: &transformed_target_vector,
                    infinity_response_vector: decoded_proof.infinity_response_vector(),
                    challenge_seed: &tbox_challenge_hashes.z34_challenge_hash,
                    proof_encoding: input.proof_encoding,
                },
                |proof_ring, shifted_rotation_polynomial_matrix| {
                    input.statement.build_z4_statement_products(
                        proof_ring,
                        input.parameter_set,
                        input.proof_encoding,
                        input.matrix_coefficient_representation,
                        shifted_rotation_polynomial_matrix,
                    )
                },
            )?;
            apply_tbox_z3_response_relations_for_statement_shape(
                tbox_accumulators,
                transformed_statement_rows,
                transformed_statement_columns,
                decoded_proof.euclidean_response_vector(),
                &tbox_challenge_hashes.z34_challenge_hash,
                input.proof_encoding,
            )
        },
    )?;

    let mut status_labels = vec![
        "LinearProofCanonicalBytesVerified",
        "LinearProofNormBoundsChecked",
        "AbdlopPublicParametersExpanded",
        "AbdlopLinearOpeningRecovered",
        "TboxZ34ChallengeUpdated",
        "TboxGeneratorChallengeUpdated",
        "StructuredLinearStatementHashTranscript",
        "QuadraticAccumulatorHelpersChecked",
        "TboxRelationBuildersChecked",
        "TboxResponseRelationBuildersChecked",
        "ManyQuadraticEquationsFolded",
        "QuadraticChallengeRecomputed",
    ];
    status_labels.extend(linear_proof_claim_boundary_status_labels(
        input.proof_encoding,
    ));

    Ok(json!(status_labels))
}

pub(super) fn validate_streamed_statement_shape<Statement>(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement: &Statement,
) -> CanonicalResult<()>
where
    Statement: StreamedLinearProofStatement,
{
    source_polynomial_split_factor(parameter_set, proof_encoding)?;
    if statement.source_statement_rows() != parameter_set.statement_rows
        || statement.source_statement_columns() != parameter_set.statement_columns
    {
        return Err(invalid_vector(
            "streamed linear statement shape does not match the parameter set",
        ));
    }
    if statement.target_vector_coefficients().len() != parameter_set.statement_rows {
        return Err(invalid_vector(
            "streamed linear statement target length does not match the parameter set",
        ));
    }

    Ok(())
}
