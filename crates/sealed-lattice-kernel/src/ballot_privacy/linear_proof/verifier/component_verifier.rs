use serde_json::{Value, json};

use super::vector_case::LinearProofVectorCase;
use super::vector_case_verifier::invalid_vector;

use crate::{
    ballot_privacy::linear_proof::{
        abdlop::validate_abdlop_linear_opening,
        abdlop_commitment::hash_abdlop_commitment,
        many_quadratic::{build_many_quadratic_equations, fold_many_quadratic_equations},
        norms::validate_norms,
        parameters::{
            LinearProofEncoding, LinearProofParameterSet, linear_proof_claim_boundary_status_labels,
        },
        proof_coder::{
            DecodedLinearProof, LinearProofBytes, decode_linear_proof, encode_linear_proof,
        },
        public_parameters::derive_default_abdlop_public_parameters,
        quadratic_challenge::validate_quadratic_challenge,
        sparse_statement::{
            derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation,
            transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
            transform_sparse_target_vector_to_proof_ring,
        },
        statement::{
            LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
            StreamedLinearProofStatement,
            derive_linear_statement_transcript_with_matrix_coefficient_representation,
            derive_transformed_statement_matrix_with_coefficient_representation,
            derive_transformed_target_vector, source_polynomial_split_factor,
        },
        tbox::validate_tbox_public_checks,
        tbox_relations::{
            TboxRelationAccumulatorSet, TboxZ4ResponseRelationInputs,
            apply_tbox_z3_response_relations, apply_tbox_z3_response_relations_for_statement_shape,
            apply_tbox_z3_response_relations_sparse, apply_tbox_z4_response_relations,
            apply_tbox_z4_response_relations_sparse,
            apply_tbox_z4_response_relations_with_product_builder, build_tbox_prefix_accumulators,
        },
        transcript::{
            LinearProofPreflightTranscriptInput, compute_linear_proof_preflight_transcript,
        },
    },
    ballot_privacy::{
        BALLOT_PRIVACY_PROOF_BACKEND_AVAILABLE, describe_proof_backend,
        polynomial_matrix::PolynomialMatrix, polynomial_ring::PolynomialRing,
        polynomial_vector::PolynomialVector, sparse_polynomial_matrix::SparsePolynomialMatrix,
    },
    encoding::CanonicalResult,
    transcript_core::decode_hex,
};

mod relation;

use relation::{
    DecodedProofRelationVerificationInput, LinearProofRelationCoreInput,
    compute_preflight_transcript_value, decode_statement_matrix, decode_target_vector,
    verify_linear_proof_relation_core,
};
pub(crate) use relation::{
    verify_sparse_linear_proof_components, verify_streamed_linear_proof_components,
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
        validate_norms(decoded_proof, proof_encoding)?;
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
