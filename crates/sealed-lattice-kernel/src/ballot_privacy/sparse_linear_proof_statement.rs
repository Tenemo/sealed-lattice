use serde::{Deserialize, Serialize};
use sha3::{
    Shake128,
    digest::{ExtendableOutput, Update, XofReader},
};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    linear_proof_parameters::{LazerDemoProofEncoding, LinearProofParameterSet},
    linear_proof_statement::{
        LinearProofTargetCoefficientRepresentation, rotate_left_negacyclic_signed_polynomial,
        scale_signed_polynomial_by_source_modulus_inverse, source_polynomial_split_factor,
        split_unsigned_polynomial_into_proof_ring, transform_target_vector_to_proof_ring,
        validate_source_polynomial,
    },
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
};

const SPARSE_LINEAR_STATEMENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"sealed.vote/internal/sparse-linear-statement-v1";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SparseLinearStatementTranscript {
    pub transcript_domain: String,
    pub transformed_statement_matrix_rows: usize,
    pub transformed_statement_matrix_columns: usize,
    pub transformed_statement_matrix_nonzero_entries: usize,
    pub transformed_target_vector_length: usize,
    pub encoded_sparse_statement_bytes: usize,
    pub sparse_arithmetic_statement_hash: [u8; 32],
    pub sparse_arithmetic_statement_hash_hex: String,
    pub public_parameters_and_statement_hash: [u8; 32],
    pub public_parameters_and_statement_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstantCoefficientSparseMatrixEntry {
    pub row_index: usize,
    pub column_index: usize,
    pub constant_coefficient: u64,
}

pub fn build_constant_coefficient_sparse_source_matrix(
    parameter_set: &LinearProofParameterSet,
    entries: &[ConstantCoefficientSparseMatrixEntry],
) -> CanonicalResult<SparsePolynomialMatrix> {
    parameter_set.validate()?;
    let source_ring =
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    let mut sparse_entries = Vec::with_capacity(entries.len());
    for entry in entries {
        if entry.constant_coefficient >= parameter_set.coefficient_modulus {
            return Err(invalid_sparse_statement(
                "constant sparse statement coefficient is not canonical",
            ));
        }
        let mut coefficients = vec![0_u64; parameter_set.ring_degree];
        coefficients[0] = entry.constant_coefficient;
        sparse_entries.push(SparsePolynomialMatrixEntry::new(
            entry.row_index,
            entry.column_index,
            coefficients,
        ));
    }

    SparsePolynomialMatrix::new(
        source_ring,
        parameter_set.statement_rows,
        parameter_set.statement_columns,
        sparse_entries,
    )
}

pub fn transform_sparse_statement_matrix_to_proof_ring(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
) -> CanonicalResult<SparsePolynomialMatrix> {
    validate_sparse_statement_matrix_inputs(
        parameter_set,
        proof_encoding,
        source_statement_matrix,
    )?;
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
    )?;
    let mut transformed_entries = Vec::new();

    for source_entry in source_statement_matrix.entries() {
        let split_polynomials = split_unsigned_polynomial_into_proof_ring(
            source_entry.coefficients(),
            source_polynomial_split_factor,
        )?;
        let rotated_split_polynomials = split_polynomials
            .iter()
            .map(|polynomial| rotate_left_negacyclic_signed_polynomial(polynomial))
            .collect::<Vec<_>>();

        for output_row_offset in 0..source_polynomial_split_factor {
            for output_column_offset in 0..source_polynomial_split_factor {
                let split_index = output_row_offset as isize - output_column_offset as isize;
                let signed_polynomial = if split_index >= 0 {
                    &split_polynomials[usize::try_from(split_index).map_err(|_| {
                        invalid_sparse_statement("sparse statement split index overflowed")
                    })?]
                } else {
                    &rotated_split_polynomials[usize::try_from(
                        source_polynomial_split_factor as isize + split_index,
                    )
                    .map_err(|_| {
                        invalid_sparse_statement("sparse statement rotated split index overflowed")
                    })?]
                };
                let transformed_coefficients = scale_signed_polynomial_by_source_modulus_inverse(
                    signed_polynomial,
                    parameter_set,
                    proof_encoding,
                )?;
                if transformed_coefficients
                    .iter()
                    .any(|coefficient| *coefficient != 0)
                {
                    transformed_entries.push(SparsePolynomialMatrixEntry::new(
                        source_entry.row_index() * source_polynomial_split_factor
                            + output_row_offset,
                        source_entry.column_index() * source_polynomial_split_factor
                            + output_column_offset,
                        transformed_coefficients,
                    ));
                }
            }
        }
    }
    transformed_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));

    SparsePolynomialMatrix::new(
        proof_ring,
        parameter_set.statement_rows * source_polynomial_split_factor,
        parameter_set.statement_columns * source_polynomial_split_factor,
        transformed_entries,
    )
}

pub fn transform_sparse_target_vector_to_proof_ring(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
) -> CanonicalResult<PolynomialVector> {
    parameter_set.validate()?;
    proof_encoding.validate()?;
    validate_sparse_target_vector(parameter_set, target_vector_coefficients)?;
    let transformed_target_vector = transform_target_vector_to_proof_ring(
        target_vector_coefficients,
        parameter_set,
        proof_encoding,
        target_coefficient_representation,
    )?;

    PolynomialVector::new(
        PolynomialRing::new(
            proof_encoding.ring_degree,
            proof_encoding.coefficient_modulus,
        )?,
        transformed_target_vector,
    )
}

pub fn derive_sparse_linear_statement_transcript(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<SparseLinearStatementTranscript> {
    if public_randomness.len() != 32 {
        return Err(invalid_sparse_statement(
            "sparse statement public randomness must be exactly 32 bytes",
        ));
    }
    let transformed_statement_matrix = transform_sparse_statement_matrix_to_proof_ring(
        parameter_set,
        proof_encoding,
        source_statement_matrix,
    )?;
    let transformed_target_vector = transform_sparse_target_vector_to_proof_ring(
        parameter_set,
        proof_encoding,
        target_vector_coefficients,
        target_coefficient_representation,
    )?;
    let (sparse_arithmetic_statement_hash, encoded_sparse_statement_bytes) =
        hash_sparse_transformed_statement(
            parameter_set,
            proof_encoding,
            target_coefficient_representation,
            &transformed_statement_matrix,
            &transformed_target_vector,
        )?;
    let public_parameters_and_statement_hash =
        shake128_32_from_parts(public_randomness, &sparse_arithmetic_statement_hash);

    Ok(SparseLinearStatementTranscript {
        transcript_domain: String::from_utf8(SPARSE_LINEAR_STATEMENT_TRANSCRIPT_DOMAIN.to_vec())
            .map_err(|_| invalid_sparse_statement("sparse statement domain is not UTF-8"))?,
        transformed_statement_matrix_rows: transformed_statement_matrix.rows(),
        transformed_statement_matrix_columns: transformed_statement_matrix.columns(),
        transformed_statement_matrix_nonzero_entries: transformed_statement_matrix.entries().len(),
        transformed_target_vector_length: transformed_target_vector.len(),
        encoded_sparse_statement_bytes,
        sparse_arithmetic_statement_hash,
        sparse_arithmetic_statement_hash_hex: to_hex(&sparse_arithmetic_statement_hash),
        public_parameters_and_statement_hash,
        public_parameters_and_statement_hash_hex: to_hex(&public_parameters_and_statement_hash),
    })
}

fn validate_sparse_statement_matrix_inputs(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
) -> CanonicalResult<()> {
    parameter_set.validate()?;
    proof_encoding.validate()?;
    source_polynomial_split_factor(parameter_set, proof_encoding)?;
    if source_statement_matrix.rows() != parameter_set.statement_rows
        || source_statement_matrix.columns() != parameter_set.statement_columns
    {
        return Err(invalid_sparse_statement(
            "sparse statement matrix dimensions do not match the parameter set",
        ));
    }
    if source_statement_matrix.ring().degree() != parameter_set.ring_degree
        || source_statement_matrix.ring().modulus() != parameter_set.coefficient_modulus
    {
        return Err(invalid_sparse_statement(
            "sparse statement matrix ring does not match the parameter set",
        ));
    }

    Ok(())
}

fn validate_sparse_target_vector(
    parameter_set: &LinearProofParameterSet,
    target_vector_coefficients: &[Vec<u64>],
) -> CanonicalResult<()> {
    if target_vector_coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_sparse_statement(
            "sparse statement target vector length does not match the parameter set",
        ));
    }
    for target_polynomial in target_vector_coefficients {
        validate_source_polynomial(parameter_set, target_polynomial)?;
    }

    Ok(())
}

fn hash_sparse_transformed_statement(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
) -> CanonicalResult<([u8; 32], usize)> {
    let mut hasher = SparseStatementHasher::new();
    hasher.write_bytes(SPARSE_LINEAR_STATEMENT_TRANSCRIPT_DOMAIN);
    hasher.write_usize(parameter_set.ring_degree)?;
    hasher.write_usize(parameter_set.proof_system_ring_degree)?;
    hasher.write_u64(parameter_set.coefficient_modulus);
    hasher.write_usize(parameter_set.statement_rows)?;
    hasher.write_usize(parameter_set.statement_columns)?;
    hasher.write_u128(parameter_set.witness_l2_bound_squared);
    hasher.write_usize(proof_encoding.ring_degree)?;
    hasher.write_u64(proof_encoding.coefficient_modulus);
    hasher.write_usize(proof_encoding.full_size_coefficient_bit_length)?;
    hasher.write_u8(match target_coefficient_representation {
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus => 0,
        LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus => 1,
    });
    hasher.write_usize(transformed_statement_matrix.rows())?;
    hasher.write_usize(transformed_statement_matrix.columns())?;
    hasher.write_usize(transformed_statement_matrix.entries().len())?;
    for entry in transformed_statement_matrix.entries() {
        hasher.write_usize(entry.row_index())?;
        hasher.write_usize(entry.column_index())?;
        hasher.write_polynomial(entry.coefficients(), proof_encoding.coefficient_modulus)?;
    }
    hasher.write_usize(transformed_target_vector.len())?;
    for polynomial in transformed_target_vector.entries() {
        hasher.write_polynomial(polynomial, proof_encoding.coefficient_modulus)?;
    }

    Ok(hasher.finish())
}

fn shake128_32_from_parts(first_part: &[u8], second_part: &[u8]) -> [u8; 32] {
    let mut hasher = Shake128::default();
    hasher.update(first_part);
    hasher.update(second_part);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 32];
    reader.read(&mut output);

    output
}

struct SparseStatementHasher {
    hasher: Shake128,
    encoded_bytes: usize,
}

impl SparseStatementHasher {
    fn new() -> Self {
        Self {
            hasher: Shake128::default(),
            encoded_bytes: 0,
        }
    }

    fn write_bytes(&mut self, value: &[u8]) {
        self.hasher.update(value);
        self.encoded_bytes += value.len();
    }

    fn write_u8(&mut self, value: u8) {
        self.write_bytes(&[value]);
    }

    fn write_u64(&mut self, value: u64) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_u128(&mut self, value: u128) {
        self.write_bytes(&value.to_le_bytes());
    }

    fn write_usize(&mut self, value: usize) -> CanonicalResult<()> {
        self.write_u64(
            u64::try_from(value).map_err(|_| {
                invalid_sparse_statement("sparse statement size does not fit in u64")
            })?,
        );

        Ok(())
    }

    fn write_polynomial(&mut self, coefficients: &[u64], modulus: u64) -> CanonicalResult<()> {
        self.write_usize(coefficients.len())?;
        for coefficient in coefficients {
            if *coefficient >= modulus {
                return Err(invalid_sparse_statement(
                    "sparse statement transformed coefficient is not canonical",
                ));
            }
            self.write_u64(*coefficient);
        }

        Ok(())
    }

    fn finish(self) -> ([u8; 32], usize) {
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; 32];
        reader.read(&mut output);

        (output, self.encoded_bytes)
    }
}

fn invalid_sparse_statement(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        ConstantCoefficientSparseMatrixEntry, LinearProofTargetCoefficientRepresentation,
        PolynomialRing, SparsePolynomialMatrix, SparsePolynomialMatrixEntry,
        build_constant_coefficient_sparse_source_matrix, derive_sparse_linear_statement_transcript,
        transform_sparse_statement_matrix_to_proof_ring,
        transform_sparse_target_vector_to_proof_ring,
    };
    use crate::ballot_privacy::{
        linear_proof_parameters::{LinearProofParameterSet, demo_linear_proof_encoding_contract},
        linear_proof_statement::{
            derive_lazer_demo_linear_statement_transcript,
            derive_lazer_demo_transformed_statement_matrix,
            derive_lazer_demo_transformed_target_vector,
        },
    };

    fn sparse_test_parameters() -> LinearProofParameterSet {
        LinearProofParameterSet {
            profile_id: "unit-sparse-linear-statement-v1".to_string(),
            source: "unit-test".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 8,
            proof_system_ring_degree: 4,
            coefficient_modulus: 17,
            statement_rows: 2,
            statement_columns: 3,
            witness_l2_bound_squared: 64,
            expected_proof_size_bytes: None,
        }
    }

    fn sparse_test_proof_encoding()
    -> crate::ballot_privacy::linear_proof_parameters::LazerDemoProofEncoding {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.ring_degree = 4;
        proof_encoding.coefficient_modulus = 97;
        proof_encoding.full_size_coefficient_bit_length = 7;
        proof_encoding.compressed_coefficient_bit_length = 6;

        proof_encoding
    }

    fn sparse_test_matrix() -> SparsePolynomialMatrix {
        let parameter_set = sparse_test_parameters();
        SparsePolynomialMatrix::new(
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate"),
            parameter_set.statement_rows,
            parameter_set.statement_columns,
            vec![
                SparsePolynomialMatrixEntry::new(0, 1, vec![1, 0, 2, 0, 3, 0, 4, 0]),
                SparsePolynomialMatrixEntry::new(1, 0, vec![0, 5, 0, 6, 0, 7, 0, 8]),
                SparsePolynomialMatrixEntry::new(1, 2, vec![9, 0, 0, 1, 0, 0, 2, 0]),
            ],
        )
        .expect("sparse test matrix should validate")
    }

    fn dense_test_matrix() -> Vec<Vec<Vec<u64>>> {
        let parameter_set = sparse_test_parameters();
        let mut dense_matrix =
            vec![
                vec![vec![0_u64; parameter_set.ring_degree]; parameter_set.statement_columns];
                parameter_set.statement_rows
            ];
        for entry in sparse_test_matrix().entries() {
            dense_matrix[entry.row_index()][entry.column_index()] = entry.coefficients().to_vec();
        }

        dense_matrix
    }

    fn target_vector() -> Vec<Vec<u64>> {
        vec![
            vec![0, 1, 16, 2, 15, 3, 14, 4],
            vec![5, 0, 6, 0, 7, 0, 8, 0],
        ]
    }

    #[test]
    fn builds_sparse_source_matrix_from_compact_constant_entries() {
        let parameter_set = sparse_test_parameters();
        let source_matrix = build_constant_coefficient_sparse_source_matrix(
            &parameter_set,
            &[
                ConstantCoefficientSparseMatrixEntry {
                    row_index: 0,
                    column_index: 1,
                    constant_coefficient: 7,
                },
                ConstantCoefficientSparseMatrixEntry {
                    row_index: 1,
                    column_index: 2,
                    constant_coefficient: 9,
                },
            ],
        )
        .expect("compact sparse matrix should expand");

        assert_eq!(source_matrix.entries().len(), 2);
        assert_eq!(
            source_matrix.entries()[0].coefficients(),
            &[7, 0, 0, 0, 0, 0, 0, 0]
        );
        assert!(
            build_constant_coefficient_sparse_source_matrix(
                &parameter_set,
                &[ConstantCoefficientSparseMatrixEntry {
                    row_index: 0,
                    column_index: 0,
                    constant_coefficient: 17,
                }],
            )
            .expect_err("noncanonical coefficient should fail")
            .message
            .contains("not canonical")
        );
    }

    #[test]
    fn sparse_statement_transform_matches_dense_transform() {
        let parameter_set = sparse_test_parameters();
        let proof_encoding = sparse_test_proof_encoding();
        let sparse_matrix = sparse_test_matrix();
        let transformed_sparse_matrix = transform_sparse_statement_matrix_to_proof_ring(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
        )
        .expect("sparse statement should transform");
        let transformed_dense_matrix = derive_lazer_demo_transformed_statement_matrix(
            &parameter_set,
            &proof_encoding,
            &dense_test_matrix(),
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("dense statement should transform");

        assert_eq!(
            transformed_sparse_matrix
                .to_dense()
                .expect("sparse transformed matrix should densify"),
            transformed_dense_matrix
        );
    }

    #[test]
    fn sparse_target_transform_matches_dense_target_transform() {
        let parameter_set = sparse_test_parameters();
        let proof_encoding = sparse_test_proof_encoding();
        let transformed_sparse_target = transform_sparse_target_vector_to_proof_ring(
            &parameter_set,
            &proof_encoding,
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
        )
        .expect("sparse target should transform");
        let transformed_dense_target = derive_lazer_demo_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &dense_test_matrix(),
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("dense target should transform");

        assert_eq!(transformed_sparse_target, transformed_dense_target);
    }

    #[test]
    fn sparse_statement_transcript_binds_entry_position_target_and_randomness() {
        let parameter_set = sparse_test_parameters();
        let proof_encoding = sparse_test_proof_encoding();
        let sparse_matrix = sparse_test_matrix();
        let transcript = derive_sparse_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("sparse transcript should derive");
        let mut moved_entry_matrix_entries = sparse_matrix.entries().to_vec();
        moved_entry_matrix_entries[0] = SparsePolynomialMatrixEntry::new(
            0,
            0,
            moved_entry_matrix_entries[0].coefficients().to_vec(),
        );
        moved_entry_matrix_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));
        let moved_entry_matrix = SparsePolynomialMatrix::new(
            sparse_matrix.ring(),
            sparse_matrix.rows(),
            sparse_matrix.columns(),
            moved_entry_matrix_entries,
        )
        .expect("moved sparse matrix should validate");
        let moved_entry_transcript = derive_sparse_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &moved_entry_matrix,
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("moved sparse transcript should derive");
        let mut changed_target = target_vector();
        changed_target[0][0] = 1;
        let changed_target_transcript = derive_sparse_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
            &changed_target,
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("changed target transcript should derive");
        let wrong_randomness_transcript = derive_sparse_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[4_u8; 32],
        )
        .expect("wrong randomness transcript should derive");

        assert_eq!(transcript.transformed_statement_matrix_rows, 4);
        assert_eq!(transcript.transformed_statement_matrix_columns, 6);
        assert_ne!(
            transcript.sparse_arithmetic_statement_hash_hex,
            moved_entry_transcript.sparse_arithmetic_statement_hash_hex
        );
        assert_ne!(
            transcript.sparse_arithmetic_statement_hash_hex,
            changed_target_transcript.sparse_arithmetic_statement_hash_hex
        );
        assert_eq!(transcript.sparse_arithmetic_statement_hash_hex.len(), 64);
        assert_ne!(
            transcript.public_parameters_and_statement_hash_hex,
            wrong_randomness_transcript.public_parameters_and_statement_hash_hex
        );
    }

    #[test]
    fn rejects_sparse_statement_shape_mismatches() {
        let mut parameter_set = sparse_test_parameters();
        let proof_encoding = sparse_test_proof_encoding();
        let sparse_matrix = sparse_test_matrix();
        parameter_set.statement_rows = 3;

        let error = transform_sparse_statement_matrix_to_proof_ring(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
        )
        .expect_err("row mismatch should fail");

        assert!(error.message.contains("dimensions"));
    }

    #[test]
    fn dense_and_sparse_transcripts_are_intentionally_separate_domains() {
        let parameter_set = sparse_test_parameters();
        let proof_encoding = sparse_test_proof_encoding();
        let sparse_matrix = sparse_test_matrix();
        let sparse_transcript = derive_sparse_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &sparse_matrix,
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("sparse transcript should derive");
        let dense_transcript = derive_lazer_demo_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &dense_test_matrix(),
            &target_vector(),
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[3_u8; 32],
        )
        .expect("dense transcript should derive");

        assert_ne!(
            sparse_transcript.sparse_arithmetic_statement_hash_hex,
            dense_transcript.arithmetic_statement_hash_hex
        );
        assert_ne!(
            sparse_transcript.public_parameters_and_statement_hash_hex,
            dense_transcript.public_parameters_and_statement_hash_hex
        );
    }
}
