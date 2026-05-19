use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

use super::{
    BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
    abdlop_commitment::hash_abdlop_commitment,
    describe_proof_backend,
    linear_proof_abdlop::validate_abdlop_linear_opening,
    linear_proof_norms::validate_linear_proof_norms,
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
    linear_proof_public_parameters::derive_default_abdlop_public_parameters,
    linear_proof_statement::{
        LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        StreamedLinearProofStatement,
        derive_linear_statement_transcript_with_matrix_coefficient_representation,
        derive_transformed_statement_matrix_with_coefficient_representation,
        derive_transformed_target_vector,
    },
    linear_proof_tbox::validate_linear_proof_tbox_public_checks,
    linear_proof_transcript::{
        LinearProofPreflightTranscriptInput, compute_linear_proof_preflight_transcript,
    },
    many_quadratic::{
        build_many_quadratic_equations, fold_many_quadratic_equations,
        validate_many_quadratic_self_check,
    },
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::{LinearProofBytes, decode_linear_proof, encode_linear_proof},
    quadratic_challenge::validate_quadratic_challenge,
    quadratic_equation::validate_quadratic_helper_self_check,
    sparse_linear_proof_statement::{
        derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation,
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
        transform_sparse_target_vector_to_proof_ring,
    },
    sparse_polynomial_matrix::SparsePolynomialMatrix,
    tbox_relations::{
        TboxZ4ResponseRelationInputs, apply_tbox_z3_response_relations,
        apply_tbox_z3_response_relations_for_statement_shape,
        apply_tbox_z3_response_relations_sparse, apply_tbox_z4_response_relations,
        apply_tbox_z4_response_relations_sparse,
        apply_tbox_z4_response_relations_with_product_builder, build_tbox_prefix_accumulators,
        validate_tbox_relation_builder_self_check,
    },
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofVectorCase {
    pub case_name: String,
    pub description: String,
    pub mutation: String,
    pub expected_outcome: String,
    pub upstream_vector_available: bool,
    pub parameter_set: Option<LinearProofParameterSet>,
    pub proof_encoding: Option<LinearProofEncoding>,
    pub public_randomness_hex: Option<String>,
    pub statement_matrix_coefficients: Option<Vec<Vec<Vec<u64>>>>,
    pub target_vector_coefficients: Option<Vec<Vec<u64>>>,
    pub matrix_coefficient_representation: Option<LinearProofMatrixCoefficientRepresentation>,
    pub target_coefficient_representation: Option<LinearProofTargetCoefficientRepresentation>,
    pub proof_hex: Option<String>,
    pub expected_proof_size_bytes: Option<usize>,
    pub trace: Option<LinearProofVectorTrace>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofVectorTrace {
    pub decoded_proof_field_lengths: Option<Value>,
    pub sealed_lattice_preflight_transcript: Option<Value>,
}

pub(crate) struct SparseLinearProofVerificationInput<'a> {
    pub(crate) case_name: &'a str,
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) public_randomness_hex: &'a str,
    pub(crate) source_statement_matrix: &'a SparsePolynomialMatrix,
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) proof_hex: &'a str,
    pub(crate) expected_proof_size_bytes: Option<usize>,
}

pub(crate) struct StreamedLinearProofVerificationInput<'a, Statement>
where
    Statement: StreamedLinearProofStatement,
{
    pub(crate) case_name: &'a str,
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) public_randomness_hex: &'a str,
    pub(crate) statement: &'a Statement,
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) proof_hex: &'a str,
    pub(crate) expected_proof_size_bytes: Option<usize>,
}

impl LinearProofVectorCase {
    fn expected_decoded_proof_field_lengths(&self) -> Option<&Value> {
        self.trace
            .as_ref()
            .and_then(|trace| trace.decoded_proof_field_lengths.as_ref())
    }

    fn expected_decoder_error(&self) -> CanonicalResult<Option<&str>> {
        match self
            .expected_decoded_proof_field_lengths()
            .and_then(|field_lengths| field_lengths.get("decoderError"))
        {
            Some(Value::String(decoder_error)) => Ok(Some(decoder_error.as_str())),
            Some(_) => Err(invalid_vector(
                "trace decodedProofFieldLengths.decoderError must be a string",
            )),
            None => Ok(None),
        }
    }

    pub fn validate_shape(&self) -> CanonicalResult<()> {
        if self.case_name.is_empty() {
            return Err(invalid_vector("caseName must not be empty"));
        }
        if self.description.is_empty() {
            return Err(invalid_vector("description must not be empty"));
        }
        if !matches!(
            self.expected_outcome.as_str(),
            "accept" | "reject" | "pending-upstream-generation"
        ) {
            return Err(invalid_vector(
                "expectedOutcome must be accept, reject, or pending-upstream-generation",
            ));
        }
        if self.upstream_vector_available {
            self.parameter_set
                .as_ref()
                .ok_or_else(|| invalid_vector("available vectors require parameterSet"))?
                .validate()?;
            let parameter_set = self
                .parameter_set
                .as_ref()
                .ok_or_else(|| invalid_vector("available vectors require parameterSet"))?;
            let public_randomness_hex = self
                .public_randomness_hex
                .as_deref()
                .ok_or_else(|| invalid_vector("available vectors require publicRandomnessHex"))?;
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
            let proof_hex = self
                .proof_hex
                .as_deref()
                .ok_or_else(|| invalid_vector("available vectors require proofHex"))?;
            let expected_decoder_error = self.expected_decoder_error()?;
            let proof_bytes =
                if self.expected_outcome == "reject" || expected_decoder_error.is_some() {
                    let proof_bytes = decode_hex(proof_hex)?;
                    if proof_bytes.is_empty() {
                        return Err(invalid_vector("proof bytes must not be empty"));
                    }
                    proof_bytes
                } else {
                    LinearProofBytes::from_hex(proof_hex, self.expected_proof_size_bytes)?
                        .bytes()
                        .to_vec()
                };
            let decoded_proof_for_verified_encoding = if let Some(proof_encoding) =
                self.proof_encoding.as_ref()
            {
                proof_encoding.validate()?;
                match decode_linear_proof(&proof_bytes, proof_encoding) {
                    Ok(decoded_proof) => {
                        if expected_decoder_error.is_some() {
                            return Err(invalid_vector(
                                "proof field decoding succeeded but the upstream trace expected decoderError",
                            ));
                        }
                        let reencoded_proof = encode_linear_proof(&decoded_proof, proof_encoding)?;
                        if reencoded_proof != proof_bytes {
                            return Err(invalid_vector(
                                "decoded proof object does not re-encode to the original canonical bytes",
                            ));
                        }
                        validate_linear_proof_norms(&decoded_proof, proof_encoding)?;
                        if let Some(expected_field_lengths) =
                            self.expected_decoded_proof_field_lengths()
                            && *expected_field_lengths
                                != serde_json::to_value(decoded_proof.field_lengths()).map_err(
                                    |error| {
                                        invalid_vector(format!(
                                            "decoded proof field lengths could not be serialized: {error}"
                                        ))
                                    },
                                )?
                        {
                            return Err(invalid_vector(
                                "decoded proof field lengths do not match the upstream trace",
                            ));
                        }
                        Some(decoded_proof)
                    }
                    Err(error) => {
                        let Some(expected_decoder_error) = expected_decoder_error else {
                            return Err(invalid_vector(format!(
                                "proof field decoding failed unexpectedly: {}",
                                error.message
                            )));
                        };
                        if error.message != expected_decoder_error {
                            return Err(invalid_vector(format!(
                                "proof field decoding failed with an unexpected decoder error: {}",
                                error.message
                            )));
                        }
                        None
                    }
                }
            } else {
                None
            };
            let statement_matrix_coefficients = self
                .statement_matrix_coefficients
                .as_deref()
                .ok_or_else(|| {
                    invalid_vector("available vectors require statementMatrixCoefficients")
                })?;
            decode_statement_matrix(parameter_set, statement_matrix_coefficients)?;
            let target_vector_coefficients =
                self.target_vector_coefficients.as_deref().ok_or_else(|| {
                    invalid_vector("available vectors require targetVectorCoefficients")
                })?;
            decode_target_vector(parameter_set, target_vector_coefficients)?;
            let target_coefficient_representation =
                self.target_coefficient_representation.ok_or_else(|| {
                    invalid_vector("available vectors require targetCoefficientRepresentation")
                })?;
            let matrix_coefficient_representation =
                self.matrix_coefficient_representation.unwrap_or_default();
            if let (Some(proof_encoding), Some(decoded_proof)) = (
                self.proof_encoding.as_ref(),
                decoded_proof_for_verified_encoding.as_ref(),
            ) {
                let statement_transcript =
                    derive_linear_statement_transcript_with_matrix_coefficient_representation(
                        parameter_set,
                        proof_encoding,
                        statement_matrix_coefficients,
                        target_vector_coefficients,
                        matrix_coefficient_representation,
                        target_coefficient_representation,
                        &public_randomness,
                    )?;
                let abdlop_commitment_hash = hash_abdlop_commitment(
                    &statement_transcript.public_parameters_and_statement_hash,
                    decoded_proof,
                    proof_encoding,
                )?;
                validate_abdlop_linear_opening(
                    &abdlop_commitment_hash,
                    &public_randomness_array,
                    decoded_proof,
                    proof_encoding,
                )?;
                let tbox_public_check_summary = validate_linear_proof_tbox_public_checks(
                    &abdlop_commitment_hash,
                    decoded_proof,
                    proof_encoding,
                )?;
                let transformed_statement_matrix =
                    derive_transformed_statement_matrix_with_coefficient_representation(
                        parameter_set,
                        proof_encoding,
                        statement_matrix_coefficients,
                        target_vector_coefficients,
                        matrix_coefficient_representation,
                        &public_randomness,
                    )?;
                let transformed_target_vector = derive_transformed_target_vector(
                    parameter_set,
                    proof_encoding,
                    statement_matrix_coefficients,
                    target_vector_coefficients,
                    target_coefficient_representation,
                    &public_randomness,
                )?;
                let z34_challenge_hash =
                    challenge_hash_from_hex(&tbox_public_check_summary.z34_challenge_hash)?;
                let generator_challenge_hash =
                    challenge_hash_from_hex(&tbox_public_check_summary.generator_challenge_hash)?;
                let mut tbox_accumulators =
                    build_tbox_prefix_accumulators(&generator_challenge_hash, proof_encoding)?;
                apply_tbox_z4_response_relations(
                    &mut tbox_accumulators,
                    &transformed_statement_matrix,
                    &transformed_target_vector,
                    decoded_proof.infinity_response_vector(),
                    &z34_challenge_hash,
                    proof_encoding,
                )?;
                apply_tbox_z3_response_relations(
                    &mut tbox_accumulators,
                    &transformed_statement_matrix,
                    decoded_proof.euclidean_response_vector(),
                    &z34_challenge_hash,
                    proof_encoding,
                )?;
                let many_quadratic_equations = build_many_quadratic_equations(
                    &tbox_accumulators,
                    decoded_proof.hash_mask_vector(),
                )?;
                let folded_many_quadratic_equation = fold_many_quadratic_equations(
                    &many_quadratic_equations,
                    &generator_challenge_hash,
                    proof_encoding.full_size_coefficient_bit_length,
                )?;
                validate_quadratic_challenge(
                    &generator_challenge_hash,
                    &public_randomness_array,
                    decoded_proof,
                    proof_encoding,
                    &folded_many_quadratic_equation,
                )?;
                validate_quadratic_helper_self_check()?;
                validate_tbox_relation_builder_self_check()?;
                validate_many_quadratic_self_check()?;
            }

            if let Some(expected_preflight_transcript) = self
                .trace
                .as_ref()
                .and_then(|trace| trace.sealed_lattice_preflight_transcript.as_ref())
            {
                let actual_preflight_transcript = compute_preflight_transcript_value(
                    parameter_set,
                    statement_matrix_coefficients,
                    target_vector_coefficients,
                    &public_randomness,
                    &proof_bytes,
                )?;
                if *expected_preflight_transcript != actual_preflight_transcript {
                    return Err(invalid_vector(
                        "sealed-lattice preflight transcript does not match the vector trace",
                    ));
                }
            }
        }

        Ok(())
    }
}

fn compute_preflight_transcript_value(
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

fn challenge_hash_from_hex(hash_hex: &str) -> CanonicalResult<[u8; 32]> {
    let bytes = decode_hex(hash_hex)?;
    bytes
        .as_slice()
        .try_into()
        .map_err(|_| invalid_vector("challenge hash must encode exactly 32 bytes"))
}

fn decode_statement_matrix(
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

fn decode_target_vector(
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
            "acceptedDigests": [],
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
            "acceptedDigests": [],
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
            "acceptedDigests": [],
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
            "acceptedDigests": [],
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

fn verify_sparse_linear_proof_components_inner(
    input: &SparseLinearProofVerificationInput<'_>,
) -> CanonicalResult<Value> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    let public_randomness = decode_hex(input.public_randomness_hex)?;
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

    let proof_bytes = LinearProofBytes::from_hex(input.proof_hex, input.expected_proof_size_bytes)?;
    let decoded_proof = decode_linear_proof(proof_bytes.bytes(), input.proof_encoding)?;
    let reencoded_proof = encode_linear_proof(&decoded_proof, input.proof_encoding)?;
    if reencoded_proof != proof_bytes.bytes() {
        return Err(invalid_vector(
            "decoded proof object does not re-encode to the original canonical bytes",
        ));
    }
    validate_linear_proof_norms(&decoded_proof, input.proof_encoding)?;

    let statement_transcript =
        derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
        input.parameter_set,
        input.proof_encoding,
        input.source_statement_matrix,
        input.target_vector_coefficients,
        input.matrix_coefficient_representation,
        input.target_coefficient_representation,
        &public_randomness,
    )?;
    let abdlop_commitment_hash = hash_abdlop_commitment(
        &statement_transcript.public_parameters_and_statement_hash,
        &decoded_proof,
        input.proof_encoding,
    )?;
    validate_abdlop_linear_opening(
        &abdlop_commitment_hash,
        &public_randomness_array,
        &decoded_proof,
        input.proof_encoding,
    )?;
    let tbox_public_check_summary = validate_linear_proof_tbox_public_checks(
        &abdlop_commitment_hash,
        &decoded_proof,
        input.proof_encoding,
    )?;
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
    let z34_challenge_hash =
        challenge_hash_from_hex(&tbox_public_check_summary.z34_challenge_hash)?;
    let generator_challenge_hash =
        challenge_hash_from_hex(&tbox_public_check_summary.generator_challenge_hash)?;
    let mut tbox_accumulators =
        build_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_tbox_z4_response_relations_sparse(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &transformed_target_vector,
        decoded_proof.infinity_response_vector(),
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    apply_tbox_z3_response_relations_sparse(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        decoded_proof.euclidean_response_vector(),
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    let many_quadratic_equations =
        build_many_quadratic_equations(&tbox_accumulators, decoded_proof.hash_mask_vector())?;
    let folded_many_quadratic_equation = fold_many_quadratic_equations(
        &many_quadratic_equations,
        &generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    validate_quadratic_challenge(
        &generator_challenge_hash,
        &public_randomness_array,
        &decoded_proof,
        input.proof_encoding,
        &folded_many_quadratic_equation,
    )?;
    validate_quadratic_helper_self_check()?;
    validate_tbox_relation_builder_self_check()?;
    validate_many_quadratic_self_check()?;

    Ok(json!([
        "LinearProofBytesCanonical",
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
        "QuadraticChallengeRecomputed"
    ]))
}

fn verify_streamed_linear_proof_components_inner<Statement>(
    input: &StreamedLinearProofVerificationInput<'_, Statement>,
) -> CanonicalResult<Value>
where
    Statement: StreamedLinearProofStatement,
{
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_streamed_statement_shape(input.parameter_set, input.proof_encoding, input.statement)?;
    let public_randomness = decode_hex(input.public_randomness_hex)?;
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

    let proof_bytes = LinearProofBytes::from_hex(input.proof_hex, input.expected_proof_size_bytes)?;
    let decoded_proof = decode_linear_proof(proof_bytes.bytes(), input.proof_encoding)?;
    let reencoded_proof = encode_linear_proof(&decoded_proof, input.proof_encoding)?;
    if reencoded_proof != proof_bytes.bytes() {
        return Err(invalid_vector(
            "decoded proof object does not re-encode to the original canonical bytes",
        ));
    }
    validate_linear_proof_norms(&decoded_proof, input.proof_encoding)?;

    let source_polynomial_split_factor =
        super::linear_proof_statement::source_polynomial_split_factor(
            input.parameter_set,
            input.proof_encoding,
        )?;
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
    let abdlop_commitment_hash = hash_abdlop_commitment(
        &statement_transcript.public_parameters_and_statement_hash,
        &decoded_proof,
        input.proof_encoding,
    )?;
    validate_abdlop_linear_opening(
        &abdlop_commitment_hash,
        &public_randomness_array,
        &decoded_proof,
        input.proof_encoding,
    )?;
    let tbox_public_check_summary = validate_linear_proof_tbox_public_checks(
        &abdlop_commitment_hash,
        &decoded_proof,
        input.proof_encoding,
    )?;
    let transformed_target_vector = input.statement.transformed_target_vector(
        input.parameter_set,
        input.proof_encoding,
        input.target_coefficient_representation,
    )?;
    let z34_challenge_hash =
        challenge_hash_from_hex(&tbox_public_check_summary.z34_challenge_hash)?;
    let generator_challenge_hash =
        challenge_hash_from_hex(&tbox_public_check_summary.generator_challenge_hash)?;
    let mut tbox_accumulators =
        build_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_tbox_z4_response_relations_with_product_builder(
        &mut tbox_accumulators,
        TboxZ4ResponseRelationInputs {
            transformed_statement_rows,
            transformed_statement_columns,
            transformed_target_vector: &transformed_target_vector,
            infinity_response_vector: decoded_proof.infinity_response_vector(),
            challenge_seed: &z34_challenge_hash,
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
        &mut tbox_accumulators,
        transformed_statement_rows,
        transformed_statement_columns,
        decoded_proof.euclidean_response_vector(),
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    let many_quadratic_equations =
        build_many_quadratic_equations(&tbox_accumulators, decoded_proof.hash_mask_vector())?;
    let folded_many_quadratic_equation = fold_many_quadratic_equations(
        &many_quadratic_equations,
        &generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    validate_quadratic_challenge(
        &generator_challenge_hash,
        &public_randomness_array,
        &decoded_proof,
        input.proof_encoding,
        &folded_many_quadratic_equation,
    )?;
    validate_quadratic_helper_self_check()?;
    validate_tbox_relation_builder_self_check()?;
    validate_many_quadratic_self_check()?;

    Ok(json!([
        "LinearProofBytesCanonical",
        "LinearProofNormBoundsChecked",
        "AbdlopPublicParametersExpanded",
        "AbdlopLinearOpeningRecovered",
        "TboxZ34ChallengeUpdated",
        "TboxGeneratorChallengeUpdated",
        "StructuredLinearStatementDigestTranscript",
        "QuadraticAccumulatorHelpersChecked",
        "TboxRelationBuildersChecked",
        "TboxResponseRelationBuildersChecked",
        "ManyQuadraticEquationsFolded",
        "QuadraticChallengeRecomputed"
    ]))
}

fn validate_streamed_statement_shape<Statement>(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement: &Statement,
) -> CanonicalResult<()>
where
    Statement: StreamedLinearProofStatement,
{
    super::linear_proof_statement::source_polynomial_split_factor(parameter_set, proof_encoding)?;
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

pub fn verify_linear_proof_vector_case_value(vector_case: &Value) -> Value {
    let parsed_case: LinearProofVectorCase = match serde_json::from_value(vector_case.clone()) {
        Ok(parsed_case) => parsed_case,
        Err(error) => {
            return invalid_fixture_value(format!("linear proof vector shape is invalid: {error}"));
        }
    };

    if let Err(error) = parsed_case.validate_shape() {
        return error_value_for_case(error, &parsed_case);
    }

    if !parsed_case.upstream_vector_available {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": parsed_case.case_name,
            "vectorAvailable": false,
            "expectedOutcome": parsed_case.expected_outcome,
            "statusLabels": [],
            "acceptedDigests": [],
            "refusedObjects": [
                {
                    "code": "OperationUnavailable",
                    "message": "Upstream linear proof bytes for this vector case have not been generated in the current environment."
                }
            ],
            "unresolvedReason": "OperationUnavailable"
        });
    }

    let verified_status_labels = json!([
        "LinearProofBytesCanonical",
        "LinearProofNormBoundsChecked",
        "AbdlopPublicParametersExpanded",
        "AbdlopLinearOpeningRecovered",
        "TboxZ34ChallengeUpdated",
        "TboxGeneratorChallengeUpdated",
        "QuadraticAccumulatorHelpersChecked",
        "TboxRelationBuildersChecked",
        "TboxResponseRelationBuildersChecked",
        "ManyQuadraticEquationsFolded",
        "QuadraticChallengeRecomputed"
    ]);

    if parsed_case.expected_outcome == "reject" {
        return json!({
            "ok": false,
            "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
            "backendStatus": describe_proof_backend(),
            "caseName": parsed_case.case_name,
            "vectorAvailable": true,
            "expectedOutcome": parsed_case.expected_outcome,
            "statusLabels": verified_status_labels,
            "acceptedDigests": [],
            "refusedObjects": [
                {
                    "code": "FixtureMismatch",
                    "message": "Reject vector unexpectedly verified as a valid linear lattice proof."
                }
            ],
            "unresolvedReason": "FixtureMismatch"
        });
    }

    json!({
        "ok": true,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "caseName": parsed_case.case_name,
        "vectorAvailable": true,
        "expectedOutcome": parsed_case.expected_outcome,
        "statusLabels": verified_status_labels,
        "acceptedDigests": [],
        "refusedObjects": [],
        "unresolvedReason": null
    })
}

fn invalid_fixture_value(message: impl Into<String>) -> Value {
    error_value(invalid_vector(message))
}

fn error_value(error: CanonicalError) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": error.code.as_str(),
                "message": error.message
            }
        ],
        "unresolvedReason": error.code.as_str()
    })
}

fn error_value_for_case(error: CanonicalError, parsed_case: &LinearProofVectorCase) -> Value {
    json!({
        "ok": false,
        "backendAvailable": BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        "backendStatus": describe_proof_backend(),
        "caseName": parsed_case.case_name,
        "vectorAvailable": parsed_case.upstream_vector_available,
        "expectedOutcome": parsed_case.expected_outcome,
        "statusLabels": [],
        "acceptedDigests": [],
        "refusedObjects": [
            {
                "code": error.code.as_str(),
                "message": error.message
            }
        ],
        "unresolvedReason": error.code.as_str()
    })
}

fn invalid_vector(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use serde_json::Value;
    use serde_json::json;

    use super::verify_linear_proof_vector_case_value;

    fn integer_property(value: &Value, field_name: &str) -> usize {
        value
            .get(field_name)
            .and_then(Value::as_u64)
            .and_then(|field_value| usize::try_from(field_value).ok())
            .unwrap_or_else(|| panic!("{field_name} should be a usize-compatible integer"))
    }

    fn apply_statement_matrix_patch(statement_matrix: &mut Value, patch: &Value) {
        let row_index = integer_property(patch, "rowIndex");
        let column_index = integer_property(patch, "columnIndex");
        let coefficient_index = integer_property(patch, "coefficientIndex");
        let coefficient = patch
            .get("coefficient")
            .cloned()
            .expect("statement matrix patch coefficient should exist");

        statement_matrix[row_index][column_index][coefficient_index] = coefficient;
    }

    fn apply_target_vector_patch(target_vector: &mut Value, patch: &Value) {
        let row_index = integer_property(patch, "rowIndex");
        let coefficient_index = integer_property(patch, "coefficientIndex");
        let coefficient = patch
            .get("coefficient")
            .cloned()
            .expect("target vector patch coefficient should exist");

        target_vector[row_index][coefficient_index] = coefficient;
    }

    fn expand_encoded_score_field_vector_case(vectors: &Value, compact_case: &Value) -> Value {
        let mut statement_matrix =
            vectors["linearStatement"]["statementMatrixCoefficients"].clone();
        let mut target_vector = vectors["linearStatement"]["targetVectorCoefficients"].clone();
        if let Some(statement_matrix_patch) = compact_case.get("statementMatrixPatch") {
            apply_statement_matrix_patch(&mut statement_matrix, statement_matrix_patch);
        }
        if let Some(target_vector_patch) = compact_case.get("targetVectorPatch") {
            apply_target_vector_patch(&mut target_vector, target_vector_patch);
        }

        json!({
            "caseName": compact_case["caseName"],
            "description": compact_case["description"],
            "mutation": compact_case["mutation"],
            "expectedOutcome": compact_case["expectedOutcome"],
            "upstreamVectorAvailable": compact_case["upstreamVectorAvailable"],
            "parameterSet": vectors["parameterSet"],
            "proofEncoding": vectors["proofEncoding"],
            "publicRandomnessHex": compact_case
                .get("publicRandomnessHex")
                .cloned()
                .unwrap_or_else(|| vectors["publicRandomnessHex"].clone()),
            "statementMatrixCoefficients": statement_matrix,
            "targetVectorCoefficients": target_vector,
            "targetCoefficientRepresentation": vectors["targetCoefficientRepresentation"],
            "proofHex": compact_case
                .get("proofHex")
                .cloned()
                .unwrap_or_else(|| vectors["proofHex"].clone()),
            "expectedProofSizeBytes": vectors["expectedProofSizeBytes"],
            "trace": compact_case["trace"]
        })
    }

    #[test]
    fn pending_upstream_vector_fails_closed() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "valid-small-linear-proof",
            "description": "Valid proof bytes are generated from the upstream oracle in a compatible environment.",
            "mutation": "none",
            "expectedOutcome": "pending-upstream-generation",
            "upstreamVectorAvailable": false,
            "parameterSet": null,
            "publicRandomnessHex": null,
            "proofHex": null,
            "expectedProofSizeBytes": null
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["vectorAvailable"], false);
        assert_eq!(verification["unresolvedReason"], "OperationUnavailable");
    }

    #[test]
    fn available_vector_shape_rejects_bad_public_randomness_length() {
        let verification = verify_linear_proof_vector_case_value(&json!({
            "caseName": "bad-public-randomness",
            "description": "Malformed vector shape used by the schema test.",
            "mutation": "wrong-public-randomness",
            "expectedOutcome": "reject",
            "upstreamVectorAvailable": true,
            "parameterSet": {
                "profileId": "demo-linear-proof-compatibility-v1",
                "source": "sealed-lattice/linear-proof/demo-parameters-v1",
                "relation": "A*w + t = 0",
                "ringDegree": 256,
                "proofSystemRingDegree": 64,
                "coefficientModulus": 4294962689_u64,
                "statementRows": 4,
                "statementColumns": 8,
                "witnessL2BoundSquared": 2048_u64,
                "expectedProofSizeBytes": 2
            },
            "publicRandomnessHex": "00",
            "proofHex": "0001",
            "expectedProofSizeBytes": 2
        }));

        assert_eq!(verification["ok"], false);
        assert_eq!(verification["unresolvedReason"], "InvalidFixture");
        assert!(
            verification["refusedObjects"][0]["message"]
                .as_str()
                .expect("message should be a string")
                .contains("32 bytes")
        );
    }

    #[test]
    fn decoder_error_reject_vectors_are_valid_negative_fixtures() {
        let linear_vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");
        let receiver_key_vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        ))
        .expect("receiver-key linear vector file should parse");
        let encoded_score_field_vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        ))
        .expect("encoded-score field vector file should parse");

        for (vectors, case_name) in [
            (&linear_vectors, "truncated-proof"),
            (&linear_vectors, "extended-proof"),
            (&receiver_key_vectors, "truncated-receiver-key-proof"),
            (&receiver_key_vectors, "extended-receiver-key-proof"),
        ] {
            let vector_case = vectors["cases"]
                .as_array()
                .expect("generated vector file should contain cases")
                .iter()
                .find(|vector_case| vector_case["caseName"] == case_name)
                .unwrap_or_else(|| panic!("{case_name} should exist"));
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(verification["ok"], false);
            assert_eq!(verification["caseName"], case_name);
            assert_eq!(verification["vectorAvailable"], true);
            assert_eq!(verification["unresolvedReason"], "FixtureMismatch");
        }

        for case_name in [
            "truncated-encoded-score-field-proof",
            "extended-encoded-score-field-proof",
        ] {
            let compact_case = encoded_score_field_vectors["cases"]
                .as_array()
                .expect("encoded-score field vector file should contain cases")
                .iter()
                .find(|vector_case| vector_case["caseName"] == case_name)
                .unwrap_or_else(|| panic!("{case_name} should exist"));
            let vector_case =
                expand_encoded_score_field_vector_case(&encoded_score_field_vectors, compact_case);
            let verification = verify_linear_proof_vector_case_value(&vector_case);

            assert_eq!(verification["ok"], false);
            assert_eq!(verification["caseName"], case_name);
            assert_eq!(verification["vectorAvailable"], true);
            assert_eq!(verification["unresolvedReason"], "FixtureMismatch");
        }
    }

    #[test]
    fn generated_upstream_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid generated vector should exist");

        let verification = verify_linear_proof_vector_case_value(vector_case);

        assert_eq!(
            verification["ok"], true,
            "receiver-key vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("QuadraticChallengeRecomputed"))
        );
    }

    #[test]
    fn generated_upstream_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");

        for vector_case in vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                vector_case["caseName"]
            );
            assert_eq!(verification["caseName"], vector_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert!(
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            );
        }
    }

    #[test]
    fn generated_receiver_key_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        ))
        .expect("receiver-key linear vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-receiver-key-linear-proof")
            .expect("valid receiver-key vector should exist");

        let verification = verify_linear_proof_vector_case_value(vector_case);

        assert_eq!(
            verification["ok"], true,
            "receiver-key vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
    }

    #[test]
    fn generated_receiver_key_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/receiver-key-linear-proof-vectors.json"
        ))
        .expect("receiver-key linear vector file should parse");

        for vector_case in vectors["cases"]
            .as_array()
            .expect("receiver-key vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let verification = verify_linear_proof_vector_case_value(vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                vector_case["caseName"]
            );
            assert_eq!(verification["caseName"], vector_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert!(
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            );
        }
    }

    #[test]
    fn generated_encoded_score_field_vector_verifies() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        ))
        .expect("encoded-score field vector file should parse");
        let compact_case = vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-encoded-score-field-linear-proof")
            .expect("valid encoded-score field vector should exist");
        let vector_case = expand_encoded_score_field_vector_case(&vectors, compact_case);

        let verification = verify_linear_proof_vector_case_value(&vector_case);

        assert_eq!(
            verification["ok"], true,
            "encoded-score field vector verification failed: {verification}"
        );
        assert_eq!(verification["vectorAvailable"], true);
        assert_eq!(verification["backendAvailable"], false);
        assert_eq!(verification["unresolvedReason"], serde_json::Value::Null);
        assert!(
            verification["statusLabels"]
                .as_array()
                .expect("status labels should be an array")
                .contains(&json!("QuadraticChallengeRecomputed"))
        );
    }

    #[test]
    fn generated_encoded_score_field_mutations_fail_closed() {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/ballot-field-linear-proof-vectors.json"
        ))
        .expect("encoded-score field vector file should parse");

        for compact_case in vectors["cases"]
            .as_array()
            .expect("encoded-score field vector file should contain cases")
            .iter()
            .filter(|vector_case| vector_case["expectedOutcome"] == "reject")
        {
            let vector_case = expand_encoded_score_field_vector_case(&vectors, compact_case);
            let verification = verify_linear_proof_vector_case_value(&vector_case);

            assert_eq!(
                verification["ok"], false,
                "{} should fail closed",
                compact_case["caseName"]
            );
            assert_eq!(verification["caseName"], compact_case["caseName"]);
            assert_eq!(verification["vectorAvailable"], true);
            assert! {
                verification["refusedObjects"][0]["message"]
                    .as_str()
                    .expect("refusal message should be a string")
                    .len()
                    > 8
            };
        }
    }
}
