use serde::{Deserialize, Serialize};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    linear_proof_parameters::{LazerDemoProofEncoding, LinearProofParameterSet},
    linear_proof_transcript::shake128_32,
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
};

#[cfg(test)]
const LAZER_DEMO_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS: i128 = 14_960_510_030_049_216;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum LinearProofTargetCoefficientRepresentation {
    CanonicalUnsignedSourceModulus,
    CenteredSignedSourceModulus,
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

pub fn derive_lazer_demo_linear_statement_transcript(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
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

    let transformed_statement_matrix = transform_statement_matrix_to_proof_ring(
        statement_matrix_coefficients,
        parameter_set,
        proof_encoding,
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

pub(crate) fn derive_lazer_demo_transformed_statement_matrix(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    target_vector_coefficients: &[Vec<u64>],
    _target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    public_randomness: &[u8],
) -> CanonicalResult<PolynomialMatrix> {
    validate_demo_statement_inputs(
        parameter_set,
        proof_encoding,
        statement_matrix_coefficients,
        target_vector_coefficients,
        public_randomness,
    )?;
    let transformed_statement_matrix = transform_statement_matrix_to_proof_ring(
        statement_matrix_coefficients,
        parameter_set,
        proof_encoding,
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

pub(crate) fn derive_lazer_demo_transformed_target_vector(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
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

fn validate_demo_statement_inputs(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
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

fn transform_statement_matrix_to_proof_ring(
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let transformed_rows = parameter_set.statement_rows * source_polynomial_split_factor;
    let transformed_columns = parameter_set.statement_columns * source_polynomial_split_factor;
    let mut transformed_entries =
        vec![vec![0_u64; proof_encoding.ring_degree]; transformed_rows * transformed_columns];

    for (source_row_index, source_row) in statement_matrix_coefficients.iter().enumerate() {
        for (selected_column_index, source_polynomial) in source_row.iter().enumerate() {
            let split_polynomials = split_unsigned_polynomial_into_proof_ring(
                source_polynomial,
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
    proof_encoding: &LazerDemoProofEncoding,
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

pub(crate) fn split_centered_source_polynomial_into_proof_ring(
    source_polynomial: &[u64],
    source_modulus: u64,
    source_polynomial_split_factor: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    if source_modulus <= 1 || source_modulus.is_multiple_of(2) {
        return Err(invalid_statement(
            "linear statement centered target representation requires an odd source modulus",
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

fn split_polynomial_into_proof_ring(
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
    proof_encoding: &LazerDemoProofEncoding,
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

fn source_modulus_inverse_mod_proof_modulus(
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

fn positive_mod_i128(value: i128, modulus: i128) -> CanonicalResult<u64> {
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
    proof_encoding: &LazerDemoProofEncoding,
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

fn encode_transformed_statement(
    transformed_statement_matrix: &[Vec<u64>],
    transformed_target_vector: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
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

struct StatementBitWriter {
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

fn invalid_statement(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LAZER_DEMO_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS,
        LinearProofTargetCoefficientRepresentation, derive_lazer_demo_linear_statement_transcript,
        derive_lazer_demo_transformed_target_vector, source_modulus_inverse_mod_proof_modulus,
        source_polynomial_split_factor,
    };
    use crate::{
        ballot_privacy::linear_proof_parameters::{
            LazerDemoProofEncoding, LinearProofParameterSet, demo_linear_proof_encoding_contract,
            receiver_key_linear_parameter_contract,
        },
        transcript_core::decode_hex,
    };

    fn generated_vector_case(case_name: &str) -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");

        vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == case_name)
            .unwrap_or_else(|| panic!("generated vector case {case_name} should exist"))
            .clone()
    }

    fn target_coefficient_representation(
        vector_case: &serde_json::Value,
    ) -> LinearProofTargetCoefficientRepresentation {
        serde_json::from_value(vector_case["targetCoefficientRepresentation"].clone())
            .expect("target coefficient representation should deserialize")
    }

    #[test]
    fn derives_demo_statement_transcript_shape() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let parameter_set: LinearProofParameterSet =
            serde_json::from_value(vector_case["parameterSet"].clone())
                .expect("parameter set should deserialize");
        let proof_encoding: LazerDemoProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> =
            serde_json::from_value(vector_case["statementMatrixCoefficients"].clone())
                .expect("statement matrix should deserialize");
        let target_vector_coefficients: Vec<Vec<u64>> =
            serde_json::from_value(vector_case["targetVectorCoefficients"].clone())
                .expect("target vector should deserialize");
        let public_randomness = decode_hex(
            vector_case["publicRandomnessHex"]
                .as_str()
                .expect("public randomness should be present"),
        )
        .expect("public randomness should decode");

        let transcript = derive_lazer_demo_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            target_coefficient_representation(&vector_case),
            &public_randomness,
        )
        .expect("statement transcript should derive");
        let split_factor = source_polynomial_split_factor(&parameter_set, &proof_encoding)
            .expect("split factor should derive");

        assert_eq!(
            transcript.transformed_statement_matrix_rows,
            parameter_set.statement_rows * split_factor
        );
        assert_eq!(
            transcript.transformed_statement_matrix_columns,
            parameter_set.statement_columns * split_factor
        );
        assert_eq!(
            transcript.transformed_target_vector_length,
            parameter_set.statement_rows * split_factor
        );
        assert_eq!(transcript.encoded_statement_bytes, 236_545);
        assert_eq!(transcript.arithmetic_statement_hash_hex.len(), 64);
        assert_eq!(
            transcript.public_parameters_and_statement_hash_hex.len(),
            64
        );
    }

    #[test]
    fn statement_transcript_binds_matrix_target_and_public_randomness() {
        let valid_case = generated_vector_case("valid-small-linear-proof");
        let mutated_statement_case = generated_vector_case("mutated-statement-matrix");
        let mutated_target_case = generated_vector_case("mutated-target-vector");
        let wrong_randomness_case = generated_vector_case("wrong-public-randomness");

        let derive_digest = |vector_case: &serde_json::Value| {
            let parameter_set: LinearProofParameterSet =
                serde_json::from_value(vector_case["parameterSet"].clone())
                    .expect("parameter set should deserialize");
            let proof_encoding: LazerDemoProofEncoding =
                serde_json::from_value(vector_case["proofEncoding"].clone())
                    .expect("proof encoding should deserialize");
            let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> =
                serde_json::from_value(vector_case["statementMatrixCoefficients"].clone())
                    .expect("statement matrix should deserialize");
            let target_vector_coefficients: Vec<Vec<u64>> =
                serde_json::from_value(vector_case["targetVectorCoefficients"].clone())
                    .expect("target vector should deserialize");
            let public_randomness = decode_hex(
                vector_case["publicRandomnessHex"]
                    .as_str()
                    .expect("public randomness should be present"),
            )
            .expect("public randomness should decode");

            derive_lazer_demo_linear_statement_transcript(
                &parameter_set,
                &proof_encoding,
                &statement_matrix_coefficients,
                &target_vector_coefficients,
                target_coefficient_representation(vector_case),
                &public_randomness,
            )
            .expect("statement transcript should derive")
            .public_parameters_and_statement_hash_hex
        };

        let valid_digest = derive_digest(&valid_case);

        assert_ne!(valid_digest, derive_digest(&mutated_statement_case));
        assert_ne!(valid_digest, derive_digest(&mutated_target_case));
        assert_ne!(valid_digest, derive_digest(&wrong_randomness_case));
    }

    #[test]
    fn target_lowering_preserves_canonical_source_representatives() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.ring_degree = 4;
        proof_encoding.coefficient_modulus = 97;
        let parameter_set = LinearProofParameterSet {
            profile_id: "unit-linear-lowering-v1".to_string(),
            source: "unit-test".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 4,
            proof_system_ring_degree: 4,
            coefficient_modulus: 17,
            statement_rows: 1,
            statement_columns: 1,
            witness_l2_bound_squared: 1,
            expected_proof_size_bytes: None,
        };
        let zero_statement_matrix = vec![vec![vec![0_u64; 4]]];
        let transformed_target_vector = derive_lazer_demo_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &zero_statement_matrix,
            &[vec![0, 1, 16, 9]],
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[7_u8; 32],
        )
        .expect("target vector should lower");
        let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(17, 97)
            .expect("source modulus should be invertible");

        assert_eq!(
            transformed_target_vector.entries(),
            &[vec![
                0,
                u64::try_from(source_modulus_inverse).expect("inverse should fit u64"),
                u64::try_from((16 * source_modulus_inverse) % 97)
                    .expect("coefficient should fit u64"),
                u64::try_from((9 * source_modulus_inverse) % 97)
                    .expect("coefficient should fit u64"),
            ]]
        );
    }

    #[test]
    fn target_lowering_can_recover_centered_source_representatives() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.ring_degree = 4;
        proof_encoding.coefficient_modulus = 97;
        let parameter_set = LinearProofParameterSet {
            profile_id: "unit-linear-lowering-v1".to_string(),
            source: "unit-test".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 4,
            proof_system_ring_degree: 4,
            coefficient_modulus: 17,
            statement_rows: 1,
            statement_columns: 1,
            witness_l2_bound_squared: 1,
            expected_proof_size_bytes: None,
        };
        let zero_statement_matrix = vec![vec![vec![0_u64; 4]]];
        let transformed_target_vector = derive_lazer_demo_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &zero_statement_matrix,
            &[vec![0, 1, 16, 9]],
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &[7_u8; 32],
        )
        .expect("target vector should lower");
        let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(17, 97)
            .expect("source modulus should be invertible");
        let scaled_negative_one =
            97_u64 - u64::try_from(source_modulus_inverse).expect("inverse should fit u64");
        let scaled_negative_eight = (97_i128 - (8 * source_modulus_inverse) % 97) % 97;

        assert_eq!(
            transformed_target_vector.entries(),
            &[vec![
                0,
                u64::try_from(source_modulus_inverse).expect("inverse should fit u64"),
                scaled_negative_one,
                u64::try_from(scaled_negative_eight).expect("coefficient should fit u64"),
            ]]
        );
    }

    #[test]
    fn source_modulus_inverse_is_parameterized_by_the_relation_modulus() {
        let proof_modulus = 36_028_797_018_964_597;
        let demo_source_modulus = 4_294_962_689;
        let receiver_key_source_modulus = 12_289;

        let demo_inverse =
            source_modulus_inverse_mod_proof_modulus(demo_source_modulus, proof_modulus)
                .expect("demo source modulus should be invertible");
        let receiver_key_inverse =
            source_modulus_inverse_mod_proof_modulus(receiver_key_source_modulus, proof_modulus)
                .expect("receiver-key source modulus should be invertible");

        assert_eq!(
            demo_inverse,
            LAZER_DEMO_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS
        );
        assert_ne!(demo_inverse, receiver_key_inverse);
        assert_eq!(
            (demo_inverse * i128::from(demo_source_modulus)) % i128::from(proof_modulus),
            1
        );
        assert_eq!(
            (receiver_key_inverse * i128::from(receiver_key_source_modulus))
                % i128::from(proof_modulus),
            1
        );
    }

    #[test]
    fn receiver_key_parameter_contract_lowers_to_the_proof_ring_shape() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = demo_linear_proof_encoding_contract();
        let zero_polynomial = vec![0_u64; parameter_set.ring_degree];
        let mut statement_matrix_coefficients =
            vec![
                vec![zero_polynomial.clone(); parameter_set.statement_columns];
                parameter_set.statement_rows
            ];
        statement_matrix_coefficients[0][0][0] = 1;
        statement_matrix_coefficients[1][4][0] = 1;
        let target_vector_coefficients = vec![zero_polynomial; parameter_set.statement_rows];
        let public_randomness = [7_u8; 32];

        let transcript = derive_lazer_demo_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("receiver-key statement should lower into the proof ring");

        assert_eq!(
            source_polynomial_split_factor(&parameter_set, &proof_encoding)
                .expect("receiver-key split factor should derive"),
            4
        );
        assert_eq!(transcript.transformed_statement_matrix_rows, 16);
        assert_eq!(transcript.transformed_statement_matrix_columns, 32);
        assert_eq!(transcript.transformed_target_vector_length, 16);
        assert_eq!(transcript.arithmetic_statement_hash_hex.len(), 64);
    }
}
