use serde_json::{Value, json};

use super::vector_case::LinearProofVectorCase;
use super::vector_case_verifier::invalid_vector;

use crate::{
    ballot_privacy::{
        BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE,
        abdlop_commitment::hash_abdlop_commitment,
        describe_proof_backend,
        linear_proof_abdlop::validate_abdlop_linear_opening,
        linear_proof_norms::validate_linear_proof_norms,
        linear_proof_parameters::{
            LinearProofEncoding, LinearProofParameterSet, linear_proof_claim_boundary_status_labels,
        },
        linear_proof_public_parameters::derive_default_abdlop_public_parameters,
        linear_proof_statement::{
            LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
            StreamedLinearProofStatement,
            derive_linear_statement_transcript_with_matrix_coefficient_representation,
            derive_transformed_statement_matrix_with_coefficient_representation,
            derive_transformed_target_vector, source_polynomial_split_factor,
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
        proof_coder::{
            DecodedLinearProof, LinearProofBytes, decode_linear_proof, encode_linear_proof,
        },
        quadratic_challenge::validate_quadratic_challenge,
        quadratic_equation::validate_quadratic_helper_self_check,
        sparse_linear_proof_statement::{
            derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation,
            transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
            transform_sparse_target_vector_to_proof_ring,
        },
        sparse_polynomial_matrix::SparsePolynomialMatrix,
        tbox_relations::{
            TboxRelationAccumulatorSet, TboxZ4ResponseRelationInputs,
            apply_tbox_z3_response_relations, apply_tbox_z3_response_relations_for_statement_shape,
            apply_tbox_z3_response_relations_sparse, apply_tbox_z4_response_relations,
            apply_tbox_z4_response_relations_sparse,
            apply_tbox_z4_response_relations_with_product_builder, build_tbox_prefix_accumulators,
            validate_tbox_relation_builder_self_check,
        },
    },
    encoding::CanonicalResult,
    transcript_core::decode_hex,
};

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
    pub fn validate_and_verify(&self) -> CanonicalResult<()> {
        self.validate_case_metadata()?;
        if self.upstream_vector_available {
            self.validate_available_vector()?;
        }

        Ok(())
    }

    fn validate_available_vector(&self) -> CanonicalResult<()> {
        let parameter_set = self.required_parameter_set()?;
        parameter_set.validate()?;
        let (public_randomness, public_randomness_array) = self.decode_public_randomness()?;
        derive_default_abdlop_public_parameters(&public_randomness_array)?;

        let proof_hex = self
            .proof_hex
            .as_deref()
            .ok_or_else(|| invalid_vector("available vectors require proofHex"))?;
        let expected_decoder_error = self.expected_decoder_error()?;
        let proof_bytes = self.decode_vector_proof_bytes(proof_hex, expected_decoder_error)?;
        let decoded_proof_for_verified_encoding =
            self.decode_and_validate_proof_encoding(&proof_bytes, expected_decoder_error)?;

        let statement_matrix_coefficients = self.required_statement_matrix_coefficients()?;
        decode_statement_matrix(parameter_set, statement_matrix_coefficients)?;
        let target_vector_coefficients = self.required_target_vector_coefficients()?;
        decode_target_vector(parameter_set, target_vector_coefficients)?;
        let target_coefficient_representation =
            self.required_target_coefficient_representation()?;
        let matrix_coefficient_representation =
            self.matrix_coefficient_representation.unwrap_or_default();

        if let (Some(proof_encoding), Some(decoded_proof)) = (
            self.proof_encoding.as_ref(),
            decoded_proof_for_verified_encoding.as_ref(),
        ) {
            self.verify_decoded_proof_relations(DecodedProofRelationVerificationInput {
                parameter_set,
                proof_encoding,
                statement_matrix_coefficients,
                target_vector_coefficients,
                matrix_coefficient_representation,
                target_coefficient_representation,
                public_randomness: &public_randomness,
                public_randomness_array: &public_randomness_array,
                decoded_proof,
            })?;
        }

        self.validate_preflight_trace(
            parameter_set,
            statement_matrix_coefficients,
            target_vector_coefficients,
            &public_randomness,
            &proof_bytes,
        )
    }

    fn required_parameter_set(&self) -> CanonicalResult<&LinearProofParameterSet> {
        self.parameter_set
            .as_ref()
            .ok_or_else(|| invalid_vector("available vectors require parameterSet"))
    }

    fn decode_public_randomness(&self) -> CanonicalResult<(Vec<u8>, [u8; 32])> {
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
        let public_randomness_array = public_randomness
            .as_slice()
            .try_into()
            .map_err(|_| invalid_vector("publicRandomnessHex must encode exactly 32 bytes"))?;

        Ok((public_randomness, public_randomness_array))
    }

    fn decode_vector_proof_bytes(
        &self,
        proof_hex: &str,
        expected_decoder_error: Option<&str>,
    ) -> CanonicalResult<Vec<u8>> {
        if self.expected_outcome == "reject" || expected_decoder_error.is_some() {
            let proof_bytes = decode_hex(proof_hex)?;
            if proof_bytes.is_empty() {
                return Err(invalid_vector("proof bytes must not be empty"));
            }
            return Ok(proof_bytes);
        }

        LinearProofBytes::from_hex(proof_hex, self.expected_proof_size_bytes)
            .map(|proof_bytes| proof_bytes.bytes().to_vec())
    }

    fn decode_and_validate_proof_encoding(
        &self,
        proof_bytes: &[u8],
        expected_decoder_error: Option<&str>,
    ) -> CanonicalResult<Option<DecodedLinearProof>> {
        let Some(proof_encoding) = self.proof_encoding.as_ref() else {
            return Ok(None);
        };

        proof_encoding.validate()?;
        match decode_linear_proof(proof_bytes, proof_encoding) {
            Ok(decoded_proof) => {
                self.validate_decoded_proof_bytes(
                    &decoded_proof,
                    proof_encoding,
                    proof_bytes,
                    expected_decoder_error,
                )?;
                Ok(Some(decoded_proof))
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
                Ok(None)
            }
        }
    }

    fn validate_decoded_proof_bytes(
        &self,
        decoded_proof: &DecodedLinearProof,
        proof_encoding: &LinearProofEncoding,
        proof_bytes: &[u8],
        expected_decoder_error: Option<&str>,
    ) -> CanonicalResult<()> {
        if expected_decoder_error.is_some() {
            return Err(invalid_vector(
                "proof field decoding succeeded but the upstream trace expected decoderError",
            ));
        }
        let reencoded_proof = encode_linear_proof(decoded_proof, proof_encoding)?;
        if reencoded_proof != proof_bytes {
            return Err(invalid_vector(
                "decoded proof object does not re-encode to the original canonical bytes",
            ));
        }
        validate_linear_proof_norms(decoded_proof, proof_encoding)?;
        self.validate_expected_decoded_proof_field_lengths(decoded_proof)
    }

    fn validate_expected_decoded_proof_field_lengths(
        &self,
        decoded_proof: &DecodedLinearProof,
    ) -> CanonicalResult<()> {
        if let Some(expected_field_lengths) = self.expected_decoded_proof_field_lengths()
            && *expected_field_lengths
                != serde_json::to_value(decoded_proof.field_lengths()).map_err(|error| {
                    invalid_vector(format!(
                        "decoded proof field lengths could not be serialized: {error}"
                    ))
                })?
        {
            return Err(invalid_vector(
                "decoded proof field lengths do not match the upstream trace",
            ));
        }

        Ok(())
    }

    fn required_statement_matrix_coefficients(&self) -> CanonicalResult<&[Vec<Vec<u64>>]> {
        self.statement_matrix_coefficients
            .as_deref()
            .ok_or_else(|| invalid_vector("available vectors require statementMatrixCoefficients"))
    }

    fn required_target_vector_coefficients(&self) -> CanonicalResult<&[Vec<u64>]> {
        self.target_vector_coefficients
            .as_deref()
            .ok_or_else(|| invalid_vector("available vectors require targetVectorCoefficients"))
    }

    fn required_target_coefficient_representation(
        &self,
    ) -> CanonicalResult<LinearProofTargetCoefficientRepresentation> {
        self.target_coefficient_representation.ok_or_else(|| {
            invalid_vector("available vectors require targetCoefficientRepresentation")
        })
    }

    fn verify_decoded_proof_relations(
        &self,
        input: DecodedProofRelationVerificationInput<'_>,
    ) -> CanonicalResult<()> {
        let statement_transcript =
            derive_linear_statement_transcript_with_matrix_coefficient_representation(
                input.parameter_set,
                input.proof_encoding,
                input.statement_matrix_coefficients,
                input.target_vector_coefficients,
                input.matrix_coefficient_representation,
                input.target_coefficient_representation,
                input.public_randomness,
            )?;
        let transformed_statement_matrix =
            derive_transformed_statement_matrix_with_coefficient_representation(
                input.parameter_set,
                input.proof_encoding,
                input.statement_matrix_coefficients,
                input.target_vector_coefficients,
                input.matrix_coefficient_representation,
                input.public_randomness,
            )?;
        let transformed_target_vector = derive_transformed_target_vector(
            input.parameter_set,
            input.proof_encoding,
            input.statement_matrix_coefficients,
            input.target_vector_coefficients,
            input.target_coefficient_representation,
            input.public_randomness,
        )?;
        verify_linear_proof_relation_core(
            LinearProofRelationCoreInput {
                public_parameters_and_statement_hash: &statement_transcript
                    .public_parameters_and_statement_hash,
                public_randomness_array: input.public_randomness_array,
                decoded_proof: input.decoded_proof,
                proof_encoding: input.proof_encoding,
            },
            |tbox_accumulators, tbox_challenge_hashes| {
                apply_tbox_z4_response_relations(
                    tbox_accumulators,
                    &transformed_statement_matrix,
                    &transformed_target_vector,
                    input.decoded_proof.infinity_response_vector(),
                    &tbox_challenge_hashes.z34_challenge_hash,
                    input.proof_encoding,
                )?;
                apply_tbox_z3_response_relations(
                    tbox_accumulators,
                    &transformed_statement_matrix,
                    input.decoded_proof.euclidean_response_vector(),
                    &tbox_challenge_hashes.z34_challenge_hash,
                    input.proof_encoding,
                )
            },
        )
    }

    fn validate_preflight_trace(
        &self,
        parameter_set: &LinearProofParameterSet,
        statement_matrix_coefficients: &[Vec<Vec<u64>>],
        target_vector_coefficients: &[Vec<u64>],
        public_randomness: &[u8],
        proof_bytes: &[u8],
    ) -> CanonicalResult<()> {
        let Some(expected_preflight_transcript) = self
            .trace
            .as_ref()
            .and_then(|trace| trace.sealed_lattice_preflight_transcript.as_ref())
        else {
            return Ok(());
        };

        let actual_preflight_transcript = compute_preflight_transcript_value(
            parameter_set,
            statement_matrix_coefficients,
            target_vector_coefficients,
            public_randomness,
            proof_bytes,
        )?;
        if *expected_preflight_transcript != actual_preflight_transcript {
            return Err(invalid_vector(
                "sealed-lattice preflight transcript does not match the vector trace",
            ));
        }

        Ok(())
    }
}

struct DecodedProofRelationVerificationInput<'a> {
    parameter_set: &'a LinearProofParameterSet,
    proof_encoding: &'a LinearProofEncoding,
    statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    target_vector_coefficients: &'a [Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &'a [u8],
    public_randomness_array: &'a [u8; 32],
    decoded_proof: &'a DecodedLinearProof,
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

struct LinearProofTboxChallengeHashes {
    z34_challenge_hash: [u8; 32],
    generator_challenge_hash: [u8; 32],
}

struct LinearProofRelationCoreInput<'a> {
    public_parameters_and_statement_hash: &'a [u8; 32],
    public_randomness_array: &'a [u8; 32],
    decoded_proof: &'a DecodedLinearProof,
    proof_encoding: &'a LinearProofEncoding,
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
    validate_linear_proof_norms(&decoded_proof, proof_encoding)?;

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
    let tbox_public_check_summary = validate_linear_proof_tbox_public_checks(
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

fn verify_linear_proof_relation_core(
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
    validate_quadratic_helper_self_check()?;
    validate_tbox_relation_builder_self_check()?;
    validate_many_quadratic_self_check()
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
        "StructuredLinearStatementDigestTranscript",
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
