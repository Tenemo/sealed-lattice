#[cfg(test)]
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
    parameters::{LinearProofEncoding, LinearProofParameterSet},
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
    statement::{
        LinearProofMatrixCoefficientRepresentation, LinearProofTargetCoefficientRepresentation,
        LinearStatementTranscript, rotate_left_negacyclic_signed_polynomial,
        scale_signed_polynomial_by_source_modulus_inverse, source_polynomial_split_factor,
        split_source_polynomial_into_proof_ring_with_coefficient_representation,
        transform_target_vector_to_proof_ring, validate_source_polynomial,
    },
};

#[cfg(test)]
const SPARSE_LINEAR_STATEMENT_TRANSCRIPT_DOMAIN: &[u8] =
    b"sealed.vote/internal/sparse-linear-statement-v1";

#[cfg(test)]
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

#[cfg(test)]
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ConstantCoefficientSparseMatrixEntry {
    pub row_index: usize,
    pub column_index: usize,
    pub constant_coefficient: u64,
}

#[cfg(test)]
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

#[cfg(test)]
pub fn transform_sparse_statement_matrix_to_proof_ring(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
) -> CanonicalResult<SparsePolynomialMatrix> {
    transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
        parameter_set,
        proof_encoding,
        source_statement_matrix,
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
    )
}

pub fn transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
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
        let split_polynomials =
            split_source_polynomial_into_proof_ring_with_coefficient_representation(
                source_entry.coefficients(),
                parameter_set.coefficient_modulus,
                source_polynomial_split_factor,
                matrix_coefficient_representation,
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
    proof_encoding: &LinearProofEncoding,
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

#[cfg(test)]
pub fn derive_sparse_linear_statement_transcript(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<SparseLinearStatementTranscript> {
    derive_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
        parameter_set,
        proof_encoding,
        source_statement_matrix,
        target_vector_coefficients,
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        target_coefficient_representation,
        public_randomness,
    )
}

#[cfg(test)]
pub fn derive_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector_coefficients: &[Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<SparseLinearStatementTranscript> {
    if public_randomness.len() != 32 {
        return Err(invalid_sparse_statement(
            "sparse statement public randomness must be exactly 32 bytes",
        ));
    }
    let transformed_statement_matrix =
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
            parameter_set,
            proof_encoding,
            source_statement_matrix,
            matrix_coefficient_representation,
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

#[cfg(test)]
pub fn derive_dense_compatible_sparse_linear_statement_transcript(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<LinearStatementTranscript> {
    derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
        parameter_set,
        proof_encoding,
        source_statement_matrix,
        target_vector_coefficients,
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        target_coefficient_representation,
        public_randomness,
    )
}

pub fn derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_statement_matrix: &SparsePolynomialMatrix,
    target_vector_coefficients: &[Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<LinearStatementTranscript> {
    if public_randomness.len() != 32 {
        return Err(invalid_sparse_statement(
            "sparse statement public randomness must be exactly 32 bytes",
        ));
    }
    let transformed_statement_matrix =
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
            parameter_set,
            proof_encoding,
            source_statement_matrix,
            matrix_coefficient_representation,
        )?;
    let transformed_target_vector = transform_sparse_target_vector_to_proof_ring(
        parameter_set,
        proof_encoding,
        target_vector_coefficients,
        target_coefficient_representation,
    )?;
    let (arithmetic_statement_hash, encoded_statement_bytes) =
        hash_sparse_transformed_statement_as_dense(
            proof_encoding,
            &transformed_statement_matrix,
            &transformed_target_vector,
        )?;
    let public_parameters_and_statement_hash =
        shake128_32_from_parts(public_randomness, &arithmetic_statement_hash);

    Ok(LinearStatementTranscript {
        transformed_statement_matrix_rows: transformed_statement_matrix.rows(),
        transformed_statement_matrix_columns: transformed_statement_matrix.columns(),
        transformed_target_vector_length: transformed_target_vector.len(),
        encoded_statement_bytes,
        arithmetic_statement_hash,
        arithmetic_statement_hash_hex: to_hex(&arithmetic_statement_hash),
        public_parameters_and_statement_hash,
        public_parameters_and_statement_hash_hex: to_hex(&public_parameters_and_statement_hash),
    })
}

fn validate_sparse_statement_matrix_inputs(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
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

#[cfg(test)]
fn hash_sparse_transformed_statement(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
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

fn hash_sparse_transformed_statement_as_dense(
    proof_encoding: &LinearProofEncoding,
    transformed_statement_matrix: &SparsePolynomialMatrix,
    transformed_target_vector: &PolynomialVector,
) -> CanonicalResult<([u8; 32], usize)> {
    proof_encoding.validate()?;
    if transformed_statement_matrix.ring() != transformed_target_vector.ring() {
        return Err(invalid_sparse_statement(
            "dense-compatible sparse statement matrix and target rings do not match",
        ));
    }
    if transformed_statement_matrix.rows() != transformed_target_vector.len() {
        return Err(invalid_sparse_statement(
            "dense-compatible sparse statement target length does not match matrix rows",
        ));
    }

    let zero_polynomial = vec![0_u64; proof_encoding.ring_degree];
    let mut writer = DenseCompatibleStatementBitHasher::new();
    let mut entry_index = 0_usize;
    for row_index in 0..transformed_statement_matrix.rows() {
        for column_index in 0..transformed_statement_matrix.columns() {
            let polynomial = match transformed_statement_matrix.entries().get(entry_index) {
                Some(entry)
                    if entry.row_index() == row_index && entry.column_index() == column_index =>
                {
                    entry_index += 1;
                    entry.coefficients()
                }
                _ => &zero_polynomial,
            };
            writer.write_polynomial(polynomial, proof_encoding)?;
        }
    }
    if entry_index != transformed_statement_matrix.entries().len() {
        return Err(invalid_sparse_statement(
            "dense-compatible sparse statement entries are not in row-major order",
        ));
    }
    for polynomial in transformed_target_vector.entries() {
        writer.write_polynomial(polynomial, proof_encoding)?;
    }

    writer.finish()
}

fn shake128_32_from_parts(first_part: &[u8], second_part: &[u8]) -> [u8; 32] {
    // LaZer-compatible fixed-width composition: current callers pass two
    // 32-byte values. Do not reuse this helper for variable-length transcripts.
    let mut hasher = Shake128::default();
    hasher.update(first_part);
    hasher.update(second_part);
    let mut reader = hasher.finalize_xof();
    let mut output = [0_u8; 32];
    reader.read(&mut output);

    output
}

#[cfg(test)]
struct SparseStatementHasher {
    hasher: Shake128,
    encoded_bytes: usize,
}

struct DenseCompatibleStatementBitHasher {
    hasher: Shake128,
    byte_value: u8,
    bit_offset_in_byte: usize,
    encoded_bytes: usize,
}

impl DenseCompatibleStatementBitHasher {
    fn new() -> Self {
        Self {
            hasher: Shake128::default(),
            byte_value: 0,
            bit_offset_in_byte: 0,
            encoded_bytes: 0,
        }
    }

    fn write_polynomial(
        &mut self,
        polynomial: &[u64],
        proof_encoding: &LinearProofEncoding,
    ) -> CanonicalResult<()> {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_sparse_statement(
                "dense-compatible sparse statement transformed polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            if *coefficient >= proof_encoding.coefficient_modulus {
                return Err(invalid_sparse_statement(
                    "dense-compatible sparse statement transformed coefficient is not canonical",
                ));
            }
            self.write_unsigned_little_endian_bits(
                *coefficient,
                proof_encoding.full_size_coefficient_bit_length,
            )?;
        }

        Ok(())
    }

    fn write_unsigned_little_endian_bits(
        &mut self,
        value: u64,
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bit_count == 0 || bit_count > 63 {
            return Err(invalid_sparse_statement(
                "dense-compatible sparse statement coder bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_sparse_statement(
                "dense-compatible sparse statement coefficient does not fit in the requested bit length",
            ));
        }
        for bit_index in 0..bit_count {
            self.write_bit(((value >> bit_index) & 1) as u8)?;
        }

        Ok(())
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_sparse_statement(
                "dense-compatible sparse statement bit must be zero or one",
            ));
        }
        if bit == 1 {
            self.byte_value |= 1_u8 << self.bit_offset_in_byte;
        }
        self.bit_offset_in_byte += 1;
        if self.bit_offset_in_byte == 8 {
            self.flush_byte();
        }

        Ok(())
    }

    fn flush_byte(&mut self) {
        self.hasher.update(&[self.byte_value]);
        self.byte_value = 0;
        self.bit_offset_in_byte = 0;
        self.encoded_bytes += 1;
    }

    fn finish(mut self) -> CanonicalResult<([u8; 32], usize)> {
        self.write_bit(1)?;
        while self.bit_offset_in_byte != 0 {
            self.write_bit(0)?;
        }
        let mut reader = self.hasher.finalize_xof();
        let mut output = [0_u8; 32];
        reader.read(&mut output);

        Ok((output, self.encoded_bytes))
    }
}

#[cfg(test)]
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
mod tests;
