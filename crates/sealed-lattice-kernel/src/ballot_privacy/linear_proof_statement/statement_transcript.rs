use serde::{Deserialize, Serialize};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
    linear_proof_transcript::shake128_32,
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
};

#[cfg(test)]
pub(super) const LINEAR_PROOF_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS: i128 =
    14_960_510_030_049_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinearProofTargetCoefficientRepresentation {
    CanonicalUnsignedSourceModulus,
    CenteredSignedSourceModulus,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinearProofMatrixCoefficientRepresentation {
    CanonicalUnsignedSourceModulus,
    CenteredSignedSourceModulus,
}

impl Default for LinearProofMatrixCoefficientRepresentation {
    fn default() -> Self {
        Self::CanonicalUnsignedSourceModulus
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LazerDemoLinearStatementTranscript {
    pub transformed_statement_matrix_rows: usize,
    pub transformed_statement_matrix_columns: usize,
    pub transformed_target_vector_length: usize,
    pub encoded_statement_bytes: usize,
    pub arithmetic_statement_hash: [u8; 32],
    pub arithmetic_statement_hash_hex: String,
    pub public_parameters_and_statement_hash: [u8; 32],
    pub public_parameters_and_statement_hash_hex: String,
}

pub(crate) trait StreamedLinearProofStatement {
    fn source_statement_rows(&self) -> usize;

    fn source_statement_columns(&self) -> usize;

    fn target_vector_coefficients(&self) -> &[Vec<u64>];

    fn validate_source_relation(
        &self,
        parameter_set: &LinearProofParameterSet,
        source_witness_vector: &PolynomialVector,
    ) -> CanonicalResult<()>;

    fn derive_statement_transcript(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
        public_randomness: &[u8],
    ) -> CanonicalResult<LazerDemoLinearStatementTranscript>;

    fn transformed_target_vector(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    ) -> CanonicalResult<PolynomialVector>;

    fn transformed_relation_output(
        &self,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        transformed_relation_witness: &PolynomialVector,
        transformed_target_vector: &PolynomialVector,
    ) -> CanonicalResult<PolynomialVector>;

    fn build_z4_statement_products(
        &self,
        proof_ring: PolynomialRing,
        parameter_set: &LinearProofParameterSet,
        proof_encoding: &LinearProofEncoding,
        matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
        shifted_rotation_polynomial_matrix: &[Vec<Vec<u64>>],
    ) -> CanonicalResult<Vec<Vec<Vec<u64>>>>;
}

pub fn derive_linear_statement_transcript(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<LazerDemoLinearStatementTranscript> {
    derive_linear_statement_transcript_with_matrix_coefficient_representation(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        target_coefficient_representation,
        public_randomness,
    )
}

pub(crate) fn derive_linear_statement_transcript_with_matrix_coefficient_representation(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<LazerDemoLinearStatementTranscript> {
    parameter_set.validate()?;
    proof_encoding.validate()?;
    validate_demo_statement_inputs(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        public_randomness,
    )?;

    let transformed_statement_matrix =
        transform_statement_matrix_to_proof_ring_with_coefficient_representation(
            statement_matrix_coefficients,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
        )?;
    let transformed_target_vector = transform_target_vector_to_proof_ring(
        target_vector_coefficients,
        parameter_set,
        proof_encoding,
        target_coefficient_representation,
    )?;
    let encoded_statement = encode_transformed_statement(
        &transformed_statement_matrix,
        &transformed_target_vector,
        proof_encoding,
    )?;
    let arithmetic_statement_hash = shake128_32(&[&encoded_statement]);
    let public_parameters_and_statement_hash =
        shake128_32(&[public_randomness, &arithmetic_statement_hash]);
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;

    Ok(LazerDemoLinearStatementTranscript {
        transformed_statement_matrix_rows: parameter_set.statement_rows
            * source_polynomial_split_factor,
        transformed_statement_matrix_columns: parameter_set.statement_columns
            * source_polynomial_split_factor,
        transformed_target_vector_length: parameter_set.statement_rows
            * source_polynomial_split_factor,
        encoded_statement_bytes: encoded_statement.len(),
        arithmetic_statement_hash,
        arithmetic_statement_hash_hex: to_hex(&arithmetic_statement_hash),
        public_parameters_and_statement_hash,
        public_parameters_and_statement_hash_hex: to_hex(&public_parameters_and_statement_hash),
    })
}

#[cfg(test)]
pub(crate) fn derive_transformed_statement_matrix(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    _target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<PolynomialMatrix> {
    derive_transformed_statement_matrix_with_coefficient_representation(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        public_randomness,
    )
}

pub(crate) fn derive_transformed_statement_matrix_with_coefficient_representation(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<PolynomialMatrix> {
    validate_demo_statement_inputs(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        public_randomness,
    )?;
    let transformed_statement_matrix =
        transform_statement_matrix_to_proof_ring_with_coefficient_representation(
            statement_matrix_coefficients,
            parameter_set,
            proof_encoding,
            matrix_coefficient_representation,
        )?;
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    PolynomialMatrix::new(
        PolynomialRing::new(
            proof_encoding.ring_degree,
            proof_encoding.coefficient_modulus,
        )?,
        parameter_set.statement_rows * source_polynomial_split_factor,
        parameter_set.statement_columns * source_polynomial_split_factor,
        transformed_statement_matrix,
    )
}

pub(crate) fn derive_transformed_target_vector(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<PolynomialVector> {
    validate_demo_statement_inputs(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        public_randomness,
    )?;
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

pub(super) fn validate_demo_statement_inputs(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    public_randomness: &[u8],
) -> CanonicalResult<()> {
    if public_randomness.len() != 32 {
        return Err(invalid_statement(
            "linear statement public randomness must be exactly 32 bytes",
        ));
    }
    source_polynomial_split_factor(parameter_set, proof_encoding)?;
    if statement_matrix_coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_statement(
            "linear statement matrix row count does not match the parameter set",
        ));
    }
    for row in statement_matrix_coefficients {
        if row.len() != parameter_set.statement_columns {
            return Err(invalid_statement(
                "linear statement matrix column count does not match the parameter set",
            ));
        }
        for polynomial in row {
            validate_source_polynomial(parameter_set, polynomial)?;
        }
    }
    if target_vector_coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_statement(
            "linear statement target vector length does not match the parameter set",
        ));
    }
    for polynomial in target_vector_coefficients {
        validate_source_polynomial(parameter_set, polynomial)?;
    }

    Ok(())
}

pub(crate) fn validate_source_polynomial(
    parameter_set: &LinearProofParameterSet,
    polynomial: &[u64],
) -> CanonicalResult<()> {
    if polynomial.len() != parameter_set.ring_degree {
        return Err(invalid_statement(
            "linear statement source polynomial degree does not match the parameter set",
        ));
    }
    if polynomial
        .iter()
        .any(|coefficient| *coefficient >= parameter_set.coefficient_modulus)
    {
        return Err(invalid_statement(
            "linear statement source polynomial contains a non-canonical coefficient",
        ));
    }

    Ok(())
}

pub(super) fn transform_statement_matrix_to_proof_ring_with_coefficient_representation(
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    matrix_coefficient_representation: LinearProofMatrixCoefficientRepresentation,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let transformed_rows = parameter_set.statement_rows * source_polynomial_split_factor;
    let transformed_columns = parameter_set.statement_columns * source_polynomial_split_factor;
    let mut transformed_entries =
        vec![vec![0_u64; proof_encoding.ring_degree]; transformed_rows * transformed_columns];

    for (source_row_index, source_row) in statement_matrix_coefficients.iter().enumerate() {
        for (selected_column_index, source_polynomial) in source_row.iter().enumerate() {
            let split_polynomials =
                split_source_polynomial_into_proof_ring_with_coefficient_representation(
                    source_polynomial,
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
                            invalid_statement("linear statement split index overflowed")
                        })?]
                    } else {
                        &rotated_split_polynomials[usize::try_from(
                            source_polynomial_split_factor as isize + split_index,
                        )
                        .map_err(|_| {
                            invalid_statement("linear statement rotated split index overflowed")
                        })?]
                    };
                    let transformed_row =
                        source_row_index * source_polynomial_split_factor + output_row_offset;
                    let transformed_column = selected_column_index * source_polynomial_split_factor
                        + output_column_offset;
                    transformed_entries
                        [transformed_row * transformed_columns + transformed_column] =
                        scale_signed_polynomial_by_source_modulus_inverse(
                            signed_polynomial,
                            parameter_set,
                            proof_encoding,
                        )?;
                }
            }
        }
    }

    Ok(transformed_entries)
}

pub(crate) fn transform_target_vector_to_proof_ring(
    target_vector_coefficients: &[Vec<u64>],
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let transformed_length = parameter_set.statement_rows * source_polynomial_split_factor;
    let mut transformed_entries = Vec::with_capacity(transformed_length);
    for source_polynomial in target_vector_coefficients {
        let split_polynomials = match target_coefficient_representation {
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus => {
                split_unsigned_polynomial_into_proof_ring(
                    source_polynomial,
                    source_polynomial_split_factor,
                )?
            }
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus => {
                split_centered_source_polynomial_into_proof_ring(
                    source_polynomial,
                    parameter_set.coefficient_modulus,
                    source_polynomial_split_factor,
                )?
            }
        };
        for signed_polynomial in split_polynomials {
            transformed_entries.push(scale_signed_polynomial_by_source_modulus_inverse(
                &signed_polynomial,
                parameter_set,
                proof_encoding,
            )?);
        }
    }

    Ok(transformed_entries)
}

pub(crate) fn split_source_polynomial_into_proof_ring_with_coefficient_representation(
    source_polynomial: &[u64],
    source_modulus: u64,
    source_polynomial_split_factor: usize,
    coefficient_representation: LinearProofMatrixCoefficientRepresentation,
) -> CanonicalResult<Vec<Vec<i128>>> {
    match coefficient_representation {
        LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus => {
            split_unsigned_polynomial_into_proof_ring(
                source_polynomial,
                source_polynomial_split_factor,
            )
        }
        LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus => {
            split_centered_source_polynomial_into_proof_ring(
                source_polynomial,
                source_modulus,
                source_polynomial_split_factor,
            )
        }
    }
}

pub(crate) fn split_centered_source_polynomial_into_proof_ring(
    source_polynomial: &[u64],
    source_modulus: u64,
    source_polynomial_split_factor: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    if source_modulus <= 1 || source_modulus.is_multiple_of(2) {
        return Err(invalid_statement(
            "linear statement centered source representation requires an odd source modulus",
        ));
    }
    let positive_representative_limit = source_modulus / 2;
    let source_modulus_value = i128::from(source_modulus);
    split_polynomial_into_proof_ring(
        source_polynomial,
        source_polynomial_split_factor,
        |coefficient| {
            if coefficient > positive_representative_limit {
                Ok(i128::from(coefficient) - source_modulus_value)
            } else {
                Ok(i128::from(coefficient))
            }
        },
    )
}

pub(crate) fn split_unsigned_polynomial_into_proof_ring(
    source_polynomial: &[u64],
    source_polynomial_split_factor: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    split_polynomial_into_proof_ring(
        source_polynomial,
        source_polynomial_split_factor,
        |coefficient| Ok(i128::from(coefficient)),
    )
}

pub(super) fn split_polynomial_into_proof_ring(
    source_polynomial: &[u64],
    source_polynomial_split_factor: usize,
    coefficient_mapper: impl Fn(u64) -> CanonicalResult<i128>,
) -> CanonicalResult<Vec<Vec<i128>>> {
    let source_degree = source_polynomial.len();
    if source_polynomial_split_factor == 0
        || !source_degree.is_multiple_of(source_polynomial_split_factor)
    {
        return Err(invalid_statement(
            "linear statement source degree does not decompose evenly",
        ));
    }
    let proof_ring_degree = source_degree / source_polynomial_split_factor;
    let mut split_polynomials =
        vec![vec![0_i128; proof_ring_degree]; source_polynomial_split_factor];

    for (component_index, split_polynomial) in split_polynomials.iter_mut().enumerate() {
        for (coefficient_index, coefficient) in split_polynomial.iter_mut().enumerate() {
            *coefficient = coefficient_mapper(
                source_polynomial
                    [source_polynomial_split_factor * coefficient_index + component_index],
            )?;
        }
    }

    Ok(split_polynomials)
}

pub(crate) fn rotate_left_negacyclic_signed_polynomial(polynomial: &[i128]) -> Vec<i128> {
    let mut rotated = vec![0_i128; polynomial.len()];
    if polynomial.is_empty() {
        return rotated;
    }
    rotated[0] = -polynomial[polynomial.len() - 1];
    rotated[1..polynomial.len()].copy_from_slice(&polynomial[..(polynomial.len() - 1)]);

    rotated
}

pub(crate) fn scale_signed_polynomial_by_source_modulus_inverse(
    signed_polynomial: &[i128],
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u64>> {
    let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(
        parameter_set.coefficient_modulus,
        proof_encoding.coefficient_modulus,
    )?;
    signed_polynomial
        .iter()
        .map(|coefficient| {
            positive_mod_i128(
                coefficient
                    .checked_mul(source_modulus_inverse)
                    .ok_or_else(|| {
                        invalid_statement("linear statement coefficient scaling overflowed")
                    })?,
                i128::from(proof_encoding.coefficient_modulus),
            )
        })
        .collect()
}

pub(super) fn source_modulus_inverse_mod_proof_modulus(
    source_modulus: u64,
    proof_modulus: u64,
) -> CanonicalResult<i128> {
    if source_modulus <= 1 || proof_modulus <= 1 {
        return Err(invalid_statement(
            "linear statement moduli must be greater than one",
        ));
    }
    let source_modulus_value = i128::from(source_modulus);
    let proof_modulus_value = i128::from(proof_modulus);
    let mut previous_remainder = source_modulus_value;
    let mut current_remainder = proof_modulus_value;
    let mut previous_coefficient = 1_i128;
    let mut current_coefficient = 0_i128;

    while current_remainder != 0 {
        let quotient = previous_remainder / current_remainder;
        let next_remainder = previous_remainder
            .checked_sub(quotient.checked_mul(current_remainder).ok_or_else(|| {
                invalid_statement("linear statement inverse computation overflowed")
            })?)
            .ok_or_else(|| invalid_statement("linear statement inverse computation overflowed"))?;
        previous_remainder = current_remainder;
        current_remainder = next_remainder;

        let next_coefficient = previous_coefficient
            .checked_sub(quotient.checked_mul(current_coefficient).ok_or_else(|| {
                invalid_statement("linear statement inverse computation overflowed")
            })?)
            .ok_or_else(|| invalid_statement("linear statement inverse computation overflowed"))?;
        previous_coefficient = current_coefficient;
        current_coefficient = next_coefficient;
    }

    if previous_remainder != 1 {
        return Err(invalid_statement(
            "linear statement source modulus is not invertible modulo the proof modulus",
        ));
    }

    positive_mod_i128(previous_coefficient, proof_modulus_value).map(i128::from)
}

pub(super) fn positive_mod_i128(value: i128, modulus: i128) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_statement(
            "linear statement proof modulus must be greater than one",
        ));
    }
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    u64::try_from(reduced)
        .map_err(|_| invalid_statement("linear statement reduced coefficient does not fit in u64"))
}

pub(crate) fn source_polynomial_split_factor(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<usize> {
    if parameter_set.proof_system_ring_degree != proof_encoding.ring_degree {
        return Err(invalid_statement(
            "linear statement proof-system ring degree does not match the proof encoding",
        ));
    }
    if proof_encoding.ring_degree == 0
        || !parameter_set
            .ring_degree
            .is_multiple_of(proof_encoding.ring_degree)
    {
        return Err(invalid_statement(
            "linear statement source ring degree does not decompose into the proof ring",
        ));
    }
    let split_factor = parameter_set.ring_degree / proof_encoding.ring_degree;
    if split_factor == 0 {
        return Err(invalid_statement(
            "linear statement source ring degree does not decompose into the proof ring",
        ));
    }

    Ok(split_factor)
}

pub(super) fn encode_transformed_statement(
    transformed_statement_matrix: &[Vec<u64>],
    transformed_target_vector: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = StatementBitWriter::new();
    for polynomial in transformed_statement_matrix
        .iter()
        .chain(transformed_target_vector.iter())
    {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_statement(
                "linear statement transformed polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            if *coefficient >= proof_encoding.coefficient_modulus {
                return Err(invalid_statement(
                    "linear statement transformed coefficient is not canonical",
                ));
            }
            writer.write_unsigned_little_endian_bits(
                *coefficient,
                proof_encoding.full_size_coefficient_bit_length,
            )?;
        }
    }

    writer.finish()
}

pub(super) struct StatementBitWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl StatementBitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_statement(
                "linear statement bit must be zero or one",
            ));
        }
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        if byte_index == self.output.len() {
            self.output.push(0);
        }
        if bit == 1 {
            self.output[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;

        Ok(())
    }

    fn write_unsigned_little_endian_bits(
        &mut self,
        value: u64,
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bit_count == 0 || bit_count > 63 {
            return Err(invalid_statement(
                "linear statement coder bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_statement(
                "linear statement coefficient does not fit in the requested bit length",
            ));
        }
        for bit_index in 0..bit_count {
            self.write_bit(((value >> bit_index) & 1) as u8)?;
        }

        Ok(())
    }

    fn finish(mut self) -> CanonicalResult<Vec<u8>> {
        self.write_bit(1)?;
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(0)?;
        }

        Ok(self.output)
    }
}

pub(super) fn invalid_statement(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}
