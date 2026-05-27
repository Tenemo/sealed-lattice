use super::*;
use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    abdlop_commitment::encode_compressed_commitment_vector,
    many_quadratic::{build_many_quadratic_equations, fold_many_quadratic_equations},
    parameters::{LinearProofEncoding, LinearProofParameterSet, linear_proof_profile_for_encoding},
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::{LinearProofComponents, encode_linear_proof_components},
    public_parameters::derive_abdlop_public_parameters,
    rng::sample_linear_proof_autostable_challenge_coefficients,
    sparse_polynomial_matrix::SparsePolynomialMatrix,
    sparse_statement::{
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
        transform_sparse_target_vector_to_proof_ring,
    },
    statement::{
        LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        StreamedLinearProofStatement,
        derive_linear_statement_transcript_with_matrix_coefficient_representation,
        derive_transformed_statement_matrix_with_coefficient_representation,
        derive_transformed_target_vector,
    },
    tbox_relations::{apply_tbox_z3_response_relations, apply_tbox_z4_response_relations},
    transcript::{shake128_32, shake128_96},
};

pub(super) const ABDLOP_OPENING_RANDOMNESS_BOUND_MODULUS: u64 = 3;
pub(super) const ABDLOP_OPENING_RANDOMNESS_BOUND_BIT_LENGTH: usize = 2;
pub(super) const RECEIVER_KEY_PROVER_RANDOMNESS_BYTES: usize = 32;
pub(super) const LINEAR_PROVER_RANDOMNESS_EXPANSION_DOMAIN: &[u8] =
    b"sealed.vote/internal/linear-proof-prover-randomness-expansion-v1";
pub(super) const LINEAR_PROVER_COMMITMENT_RANDOMNESS_LABEL: &[u8] = b"commitment-randomness";
pub(super) const LINEAR_PROVER_SUBPROTOCOL_SEED_LABEL: &[u8] = b"subprotocol-seed";
pub(super) const RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS: usize = 9;
pub(super) const RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS: usize = 2;
pub(super) const RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS: usize = 1;

pub(super) fn positive_mod_i128(value: i128, modulus: u64) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_prover(
            "linear prover modulus must be greater than one",
        ));
    }
    let modulus = i128::from(modulus);
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }

    u64::try_from(reduced)
        .map_err(|_| invalid_prover("linear prover reduced coefficient does not fit in u64"))
}

pub(super) fn invalid_prover(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

pub(crate) struct LinearProverWitnessInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8],
}

pub(crate) struct SparseLinearProverWitnessInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) source_statement_matrix: &'a SparsePolynomialMatrix,
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverWitnessSummary {
    pub(crate) relation_witness_polynomial_count: usize,
    pub(crate) short_witness_polynomial_count: usize,
    pub(crate) witness_l2_squared: u128,
    pub(crate) witness_l2_bound_squared: u128,
    pub(crate) norm_slack: u128,
}

pub(crate) struct LinearProverWitnessPreparation {
    short_witness_vector: PolynomialVector,
    summary: LinearProverWitnessSummary,
}

impl LinearProverWitnessPreparation {
    pub(crate) fn summary(&self) -> &LinearProverWitnessSummary {
        &self.summary
    }

    pub(crate) fn short_witness_polynomial_count(&self) -> usize {
        self.short_witness_vector.entries().len()
    }

    pub(super) fn short_witness_vector(&self) -> &PolynomialVector {
        &self.short_witness_vector
    }

    #[cfg(test)]
    pub(super) fn short_witness_vector_entries(&self) -> &[Vec<u64>] {
        self.short_witness_vector.entries()
    }
}

pub(crate) struct LinearProverCommitmentInput<'a> {
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) public_randomness: &'a [u8; 32],
    pub(crate) statement_transcript_hash: &'a [u8; 32],
    pub(crate) witness_preparation: &'a LinearProverWitnessPreparation,
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

pub(crate) struct LinearProverProofInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

pub(crate) struct SparseLinearProverProofInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) source_statement_matrix: &'a SparsePolynomialMatrix,
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

pub(crate) struct StreamedLinearProverProofInput<'a, Statement>
where
    Statement: StreamedLinearProofStatement,
{
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LinearProofEncoding,
    pub(crate) statement: &'a Statement,
    pub(crate) matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverProofSummary {
    pub(crate) proof_size_bytes: usize,
    pub(crate) abdlop_commitment_hash_hex: String,
    pub(crate) z34_challenge_hash_hex: String,
    pub(crate) generator_challenge_hash_hex: String,
    pub(crate) quadratic_challenge_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverProofGeneration {
    pub(crate) proof_bytes: Vec<u8>,
    pub(crate) summary: LinearProverProofSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverCommitmentSummary {
    pub(crate) compressed_commitment_polynomial_count: usize,
    pub(crate) opening_randomness_polynomial_count: usize,
    pub(crate) opening_remainder_polynomial_count: usize,
    pub(crate) prover_randomness_seed_bytes: usize,
    pub(crate) subprotocol_seed_bytes: usize,
    pub(crate) abdlop_commitment_hash_hex: String,
}

pub(crate) struct LinearProverCommitmentPreparation {
    compressed_commitment_vector: PolynomialVector,
    opening_remainder_vector: PolynomialVector,
    opening_randomness_vector: PolynomialVector,
    subprotocol_seed: [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    summary: LinearProverCommitmentSummary,
}

impl LinearProverCommitmentPreparation {
    pub(crate) fn summary(&self) -> &LinearProverCommitmentSummary {
        &self.summary
    }

    pub(crate) fn compressed_commitment_polynomial_count(&self) -> usize {
        self.compressed_commitment_vector.len()
    }

    pub(super) fn compressed_commitment_vector(&self) -> &PolynomialVector {
        &self.compressed_commitment_vector
    }

    pub(super) fn opening_remainder_vector(&self) -> &PolynomialVector {
        &self.opening_remainder_vector
    }

    pub(super) fn opening_randomness_vector(&self) -> &PolynomialVector {
        &self.opening_randomness_vector
    }

    pub(super) fn subprotocol_seed(&self) -> &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES] {
        &self.subprotocol_seed
    }

    #[cfg(test)]
    pub(super) fn compressed_commitment_vector_entries(&self) -> &[Vec<u64>] {
        self.compressed_commitment_vector.entries()
    }
}

pub(crate) fn prepare_linear_prover_witness(
    input: LinearProverWitnessInput<'_>,
) -> CanonicalResult<LinearProverWitnessPreparation> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_source_witness_shape(input.parameter_set, input.source_witness_coefficients)?;
    let source_witness_vector =
        source_witness_to_canonical_vector(input.parameter_set, input.source_witness_coefficients)?;
    let source_statement_matrix =
        source_statement_matrix(input.parameter_set, input.statement_matrix_coefficients)?;
    let source_target_vector =
        source_target_vector(input.parameter_set, input.target_vector_coefficients)?;
    let source_relation_output = source_statement_matrix
        .evaluate_linear_relation(&source_witness_vector, &source_target_vector)?;
    if !is_zero_polynomial_vector(&source_relation_output) {
        return Err(invalid_prover(
            "linear prover source witness does not satisfy A*w + t = 0",
        ));
    }

    let witness_l2_squared = source_witness_l2_squared(input.source_witness_coefficients)?;
    if witness_l2_squared > input.parameter_set.witness_l2_bound_squared {
        return Err(invalid_prover(
            "linear prover source witness exceeds the l2 bound",
        ));
    }

    let transformed_relation_witness = transform_source_witness_to_proof_ring(
        input.parameter_set,
        input.proof_encoding,
        input.source_witness_coefficients,
    )?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let transformed_witness_vector =
        PolynomialVector::new(proof_ring, transformed_relation_witness.clone())?;
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
    let _transformed_relation_output = transformed_statement_matrix
        .evaluate_linear_relation(&transformed_witness_vector, &transformed_target_vector)?;
    // Modular source rows can lift to a nonzero proof-ring residual equal to
    // the row quotient. The tbox z4 path binds that bounded residual.

    let relation_witness_polynomial_count = transformed_relation_witness.len();
    let expected_short_witness_polynomial_count = relation_witness_polynomial_count
        .checked_add(1)
        .ok_or_else(|| invalid_prover("linear prover short witness length overflowed"))?;
    if input.proof_encoding.short_response_vector_length != expected_short_witness_polynomial_count
    {
        return Err(invalid_prover(
            "linear prover witness layout does not match the proof encoding",
        ));
    }

    let norm_slack = input
        .parameter_set
        .witness_l2_bound_squared
        .checked_sub(witness_l2_squared)
        .ok_or_else(|| invalid_prover("linear prover norm slack underflowed"))?;
    let mut short_witness_entries = transformed_relation_witness;
    short_witness_entries.push(binary_expansion_polynomial(proof_ring, norm_slack)?);
    let short_witness_vector = PolynomialVector::new(proof_ring, short_witness_entries)?;
    let summary = LinearProverWitnessSummary {
        relation_witness_polynomial_count,
        short_witness_polynomial_count: expected_short_witness_polynomial_count,
        witness_l2_squared,
        witness_l2_bound_squared: input.parameter_set.witness_l2_bound_squared,
        norm_slack,
    };

    Ok(LinearProverWitnessPreparation {
        short_witness_vector,
        summary,
    })
}

pub(crate) fn prepare_sparse_linear_prover_witness(
    input: SparseLinearProverWitnessInput<'_>,
) -> CanonicalResult<LinearProverWitnessPreparation> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_source_witness_shape(input.parameter_set, input.source_witness_coefficients)?;
    if input.source_statement_matrix.rows() != input.parameter_set.statement_rows
        || input.source_statement_matrix.columns() != input.parameter_set.statement_columns
        || input.source_statement_matrix.ring().degree() != input.parameter_set.ring_degree
        || input.source_statement_matrix.ring().modulus() != input.parameter_set.coefficient_modulus
    {
        return Err(invalid_prover(
            "linear prover sparse statement matrix does not match the parameter set",
        ));
    }

    let source_witness_vector =
        source_witness_to_canonical_vector(input.parameter_set, input.source_witness_coefficients)?;
    let source_target_vector =
        source_target_vector(input.parameter_set, input.target_vector_coefficients)?;
    let source_relation_output = input
        .source_statement_matrix
        .multiply_vector(&source_witness_vector)?
        .add(&source_target_vector)?;
    if !is_zero_polynomial_vector(&source_relation_output) {
        return Err(invalid_prover(
            "linear prover source witness does not satisfy A*w + t = 0",
        ));
    }

    let witness_l2_squared = source_witness_l2_squared(input.source_witness_coefficients)?;
    if witness_l2_squared > input.parameter_set.witness_l2_bound_squared {
        return Err(invalid_prover(
            "linear prover source witness exceeds the l2 bound",
        ));
    }

    let transformed_relation_witness = transform_source_witness_to_proof_ring(
        input.parameter_set,
        input.proof_encoding,
        input.source_witness_coefficients,
    )?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let transformed_witness_vector =
        PolynomialVector::new(proof_ring, transformed_relation_witness.clone())?;
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
    let _transformed_relation_output = transformed_statement_matrix
        .multiply_vector(&transformed_witness_vector)?
        .add(&transformed_target_vector)?;
    // Modular source rows can lift to a nonzero proof-ring residual equal to
    // the row quotient. The tbox z4 path binds that bounded residual.

    let relation_witness_polynomial_count = transformed_relation_witness.len();
    let expected_short_witness_polynomial_count = relation_witness_polynomial_count
        .checked_add(1)
        .ok_or_else(|| invalid_prover("linear prover short witness length overflowed"))?;
    if input.proof_encoding.short_response_vector_length != expected_short_witness_polynomial_count
    {
        return Err(invalid_prover(
            "linear prover witness layout does not match the proof encoding",
        ));
    }

    let norm_slack = input
        .parameter_set
        .witness_l2_bound_squared
        .checked_sub(witness_l2_squared)
        .ok_or_else(|| invalid_prover("linear prover norm slack underflowed"))?;
    let mut short_witness_entries = transformed_relation_witness;
    short_witness_entries.push(binary_expansion_polynomial(proof_ring, norm_slack)?);
    let short_witness_vector = PolynomialVector::new(proof_ring, short_witness_entries)?;
    let summary = LinearProverWitnessSummary {
        relation_witness_polynomial_count,
        short_witness_polynomial_count: expected_short_witness_polynomial_count,
        witness_l2_squared,
        witness_l2_bound_squared: input.parameter_set.witness_l2_bound_squared,
        norm_slack,
    };

    Ok(LinearProverWitnessPreparation {
        short_witness_vector,
        summary,
    })
}

pub(super) fn prepare_streamed_linear_prover_witness<Statement>(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement: &Statement,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    source_witness_coefficients: &[Vec<i64>],
) -> CanonicalResult<LinearProverWitnessPreparation>
where
    Statement: StreamedLinearProofStatement,
{
    parameter_set.validate()?;
    proof_encoding.validate()?;
    validate_source_witness_shape(parameter_set, source_witness_coefficients)?;
    validate_streamed_statement_shape(parameter_set, proof_encoding, statement)?;

    let source_witness_vector =
        source_witness_to_canonical_vector(parameter_set, source_witness_coefficients)?;
    statement.validate_source_relation(parameter_set, &source_witness_vector)?;

    let witness_l2_squared = source_witness_l2_squared(source_witness_coefficients)?;
    if witness_l2_squared > parameter_set.witness_l2_bound_squared {
        return Err(invalid_prover(
            "linear prover source witness exceeds the l2 bound",
        ));
    }

    let transformed_relation_witness = transform_source_witness_to_proof_ring(
        parameter_set,
        proof_encoding,
        source_witness_coefficients,
    )?;
    let proof_ring = PolynomialRing::new(
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
    )?;
    let transformed_witness_vector =
        PolynomialVector::new(proof_ring, transformed_relation_witness.clone())?;
    let transformed_target_vector = statement.transformed_target_vector(
        parameter_set,
        proof_encoding,
        target_coefficient_representation,
    )?;
    let _transformed_relation_output = statement.transformed_relation_output(
        parameter_set,
        proof_encoding,
        matrix_coefficient_representation,
        &transformed_witness_vector,
        &transformed_target_vector,
    )?;
    // Modular source rows can lift to a nonzero proof-ring residual equal to
    // the row quotient. The tbox z4 path binds that bounded residual.

    let relation_witness_polynomial_count = transformed_relation_witness.len();
    let expected_short_witness_polynomial_count = relation_witness_polynomial_count
        .checked_add(1)
        .ok_or_else(|| invalid_prover("linear prover short witness length overflowed"))?;
    if proof_encoding.short_response_vector_length != expected_short_witness_polynomial_count {
        return Err(invalid_prover(
            "linear prover witness layout does not match the proof encoding",
        ));
    }

    let norm_slack = parameter_set
        .witness_l2_bound_squared
        .checked_sub(witness_l2_squared)
        .ok_or_else(|| invalid_prover("linear prover norm slack underflowed"))?;
    let mut short_witness_entries = transformed_relation_witness;
    short_witness_entries.push(binary_expansion_polynomial(proof_ring, norm_slack)?);
    let short_witness_vector = PolynomialVector::new(proof_ring, short_witness_entries)?;
    let summary = LinearProverWitnessSummary {
        relation_witness_polynomial_count,
        short_witness_polynomial_count: expected_short_witness_polynomial_count,
        witness_l2_squared,
        witness_l2_bound_squared: parameter_set.witness_l2_bound_squared,
        norm_slack,
    };

    Ok(LinearProverWitnessPreparation {
        short_witness_vector,
        summary,
    })
}

pub(crate) fn prepare_linear_prover_commitment(
    input: LinearProverCommitmentInput<'_>,
) -> CanonicalResult<LinearProverCommitmentPreparation> {
    input.proof_encoding.validate()?;
    if input.witness_preparation.short_witness_vector().len()
        != input.proof_encoding.short_response_vector_length
    {
        return Err(invalid_prover(
            "linear prover short witness length does not match the proof encoding",
        ));
    }
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let commitment_randomness_seed = shake128_32(&[
        LINEAR_PROVER_RANDOMNESS_EXPANSION_DOMAIN,
        LINEAR_PROVER_COMMITMENT_RANDOMNESS_LABEL,
        input.statement_transcript_hash,
        input.prover_randomness,
    ]);
    let subprotocol_seed = shake128_32(&[
        LINEAR_PROVER_RANDOMNESS_EXPANSION_DOMAIN,
        LINEAR_PROVER_SUBPROTOCOL_SEED_LABEL,
        input.statement_transcript_hash,
        input.prover_randomness,
    ]);

    let opening_randomness_vector = sample_abdlop_opening_randomness_vector(
        proof_ring,
        input.proof_encoding,
        &commitment_randomness_seed,
    )?;
    let public_parameters =
        derive_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
    let opening_randomness_prefix = PolynomialVector::new(
        proof_ring,
        opening_randomness_vector.entries()
            [..input.proof_encoding.randomness_response_vector_length]
            .to_vec(),
    )?;
    let opening_randomness_suffix = PolynomialVector::new(
        proof_ring,
        opening_randomness_vector.entries()
            [input.proof_encoding.randomness_response_vector_length..]
            .to_vec(),
    )?;
    let short_commitment_product = public_parameters
        .commitment_key_matrix
        .multiply_vector(input.witness_preparation.short_witness_vector())?;
    let opening_product = public_parameters
        .opening_key_matrix
        .multiply_vector(&opening_randomness_prefix)?;
    let uncompressed_commitment = short_commitment_product
        .add(&opening_product)?
        .add(&opening_randomness_suffix)?;
    let (compressed_commitment_vector, opening_remainder_vector) =
        power2round_abdlop_commitment(&uncompressed_commitment, input.proof_encoding)?;
    let encoded_commitment = encode_compressed_commitment_vector(
        compressed_commitment_vector.entries(),
        input.proof_encoding,
    )?;
    let abdlop_commitment_hash =
        shake128_32(&[input.statement_transcript_hash, &encoded_commitment]);
    let summary = LinearProverCommitmentSummary {
        compressed_commitment_polynomial_count: compressed_commitment_vector.len(),
        opening_randomness_polynomial_count: opening_randomness_vector.len(),
        opening_remainder_polynomial_count: opening_remainder_vector.len(),
        prover_randomness_seed_bytes: RECEIVER_KEY_PROVER_RANDOMNESS_BYTES,
        subprotocol_seed_bytes: subprotocol_seed.len(),
        abdlop_commitment_hash_hex: to_hex(&abdlop_commitment_hash),
    };

    Ok(LinearProverCommitmentPreparation {
        compressed_commitment_vector,
        opening_remainder_vector,
        opening_randomness_vector,
        subprotocol_seed,
        summary,
    })
}

pub(crate) fn generate_linear_proof(
    input: LinearProverProofInput<'_>,
) -> CanonicalResult<LinearProverProofGeneration> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    let proof_profile = linear_proof_profile_for_encoding(input.proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
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
    let witness_preparation = prepare_linear_prover_witness(LinearProverWitnessInput {
        parameter_set: input.parameter_set,
        proof_encoding: input.proof_encoding,
        statement_matrix_coefficients: input.statement_matrix_coefficients,
        target_vector_coefficients: input.target_vector_coefficients,
        matrix_coefficient_representation: input.matrix_coefficient_representation,
        target_coefficient_representation: input.target_coefficient_representation,
        source_witness_coefficients: input.source_witness_coefficients,
        public_randomness: input.public_randomness,
    })?;
    let commitment_preparation = prepare_linear_prover_commitment(LinearProverCommitmentInput {
        proof_encoding: input.proof_encoding,
        public_randomness: input.public_randomness,
        statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
        witness_preparation: &witness_preparation,
        prover_randomness: input.prover_randomness,
    })?;
    let encoded_commitment = encode_compressed_commitment_vector(
        commitment_preparation
            .compressed_commitment_vector()
            .entries(),
        input.proof_encoding,
    )?;
    let abdlop_commitment_hash = shake128_32(&[
        &statement_transcript.public_parameters_and_statement_hash,
        &encoded_commitment,
    ]);
    let public_parameters =
        derive_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
    let short_witness = witness_preparation.short_witness_vector();
    let opening_randomness = commitment_preparation.opening_randomness_vector();
    let opening_randomness_prefix = PolynomialVector::new(
        proof_ring,
        opening_randomness.entries()[..input.proof_encoding.randomness_response_vector_length]
            .to_vec(),
    )?;
    let subprotocol_seeds = shake128_96(&[commitment_preparation.subprotocol_seed()]);
    let mut z34_seed = [0_u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES];
    z34_seed.copy_from_slice(&subprotocol_seeds[..RECEIVER_KEY_PROVER_RANDOMNESS_BYTES]);

    let beta_signs = receiver_key_tbox_beta_signs(&z34_seed);
    let z34_message_vector = receiver_key_z34_message_vector(proof_ring, beta_signs)?;
    let mut target_commitment_vector = receiver_key_target_commitment_prefix(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        &z34_message_vector,
    )?;
    let z34_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let z34_challenge_hash = shake128_32(&[&abdlop_commitment_hash, &z34_challenge_encoding]);
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
    let transformed_relation_witness = PolynomialVector::new(
        proof_ring,
        short_witness.entries()[..short_witness.len() - 1].to_vec(),
    )?;
    let tbox_z4_secret = transformed_statement_matrix
        .evaluate_linear_relation(&transformed_relation_witness, &transformed_target_vector)?;
    let euclidean_response_vector = compute_receiver_key_tbox_z3_response(
        proof_ring,
        short_witness,
        beta_signs.0,
        &z34_challenge_hash,
    )?;
    let infinity_response_vector = compute_receiver_key_tbox_z4_response(
        proof_ring,
        &tbox_z4_secret,
        beta_signs.1,
        &z34_challenge_hash,
    )?;

    let hash_mask_blinding_vector =
        receiver_key_zero_message_vector(proof_ring, RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS)?;
    let hash_mask_target_commitment = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS,
        &hash_mask_blinding_vector,
    )?;
    target_commitment_vector.extend(hash_mask_target_commitment);
    let generator_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS
            ..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let generator_challenge_hash =
        shake128_32(&[&z34_challenge_hash, &generator_challenge_encoding]);

    let mut tbox_accumulators =
        build_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_tbox_z4_response_relations(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &transformed_target_vector,
        &infinity_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    apply_tbox_z3_response_relations(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &euclidean_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    let tbox_witness = build_receiver_key_tbox_witness_vector(
        proof_ring,
        short_witness,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let tbox_z34_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        z34_message_vector.entries(),
    )?;
    let folded_tbox_equations = tbox_accumulators.auto_folded_equations()?;
    let hash_mask_vector = receiver_key_hash_mask_from_tbox_equations(
        proof_ring,
        &folded_tbox_equations,
        &tbox_witness,
        &tbox_z34_witness,
    )?;
    let many_quadratic_equations =
        build_many_quadratic_equations(&tbox_accumulators, &hash_mask_vector)?;
    let many_quadratic_fold = fold_many_quadratic_equations(
        &many_quadratic_equations,
        &generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let quadratic_message_vector = receiver_key_quadratic_message_vector(
        proof_ring,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let quadratic_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        quadratic_message_vector.entries(),
    )?;
    let folded_relation_value = evaluate_quadratic_equation_equation(
        &many_quadratic_fold.folded_equation,
        &quadratic_witness,
    )?;
    if !is_zero_polynomial(&folded_relation_value) {
        return Err(invalid_prover(
            "receiver-key many-quadratic relation is not satisfied by the prover witness",
        ));
    }

    let quadratic_target_tail = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS,
        &receiver_key_zero_message_vector(
            proof_ring,
            RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS,
        )?,
    )?;
    target_commitment_vector.extend(quadratic_target_tail);
    let zero_verifier_polynomial = vec![0_u64; proof_ring.degree()];
    let zero_recovered_high_bits =
        vec![vec![0_u64; proof_ring.degree()]; input.proof_encoding.hint_vector_length];
    let quadratic_challenge_encoding = encode_quadratic_challenge_input_for_hash(
        proof_ring,
        &target_commitment_vector
            [RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS..],
        &zero_verifier_polynomial,
        &zero_recovered_high_bits,
        input.proof_encoding,
    )?;
    let quadratic_challenge_hash =
        shake128_32(&[&generator_challenge_hash, &quadratic_challenge_encoding]);
    let centered_challenge_polynomial = sample_linear_proof_autostable_challenge_coefficients(
        proof_ring.degree(),
        proof_profile.challenge_centered_bound,
        proof_profile.challenge_coefficient_bit_length,
        &quadratic_challenge_hash,
        0,
    )?;
    let challenge_polynomial =
        signed_polynomial_to_canonical(proof_ring, &centered_challenge_polynomial)?;
    let short_response_vector =
        multiply_polynomial_by_vector(proof_ring, &challenge_polynomial, short_witness)?;
    let randomness_response_vector = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        &opening_randomness_prefix,
    )?;
    let recovery_input = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        commitment_preparation.opening_remainder_vector(),
    )?;
    let hint_vector =
        make_zero_high_bits_hint(proof_ring, recovery_input.entries(), input.proof_encoding)?;
    validate_zero_high_bits_low_part(proof_ring, recovery_input.entries(), input.proof_encoding)?;

    let proof_bytes = encode_linear_proof_components(
        LinearProofComponents {
            commitment_target_vector: target_commitment_vector,
            hash_mask_vector,
            compressed_commitment_vector: commitment_preparation
                .compressed_commitment_vector()
                .entries()
                .to_vec(),
            centered_challenge_polynomial,
            hint_vector,
            short_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                short_response_vector.entries(),
            )?,
            randomness_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                randomness_response_vector.entries(),
            )?,
            euclidean_response_vector,
            infinity_response_vector,
        },
        input.proof_encoding,
    )?;
    let summary = LinearProverProofSummary {
        proof_size_bytes: proof_bytes.len(),
        abdlop_commitment_hash_hex: to_hex(&abdlop_commitment_hash),
        z34_challenge_hash_hex: to_hex(&z34_challenge_hash),
        generator_challenge_hash_hex: to_hex(&generator_challenge_hash),
        quadratic_challenge_hash_hex: to_hex(&quadratic_challenge_hash),
    };

    Ok(LinearProverProofGeneration {
        proof_bytes,
        summary,
    })
}

pub(crate) fn generate_receiver_key_linear_proof(
    input: LinearProverProofInput<'_>,
) -> CanonicalResult<LinearProverProofGeneration> {
    generate_linear_proof(input)
}
