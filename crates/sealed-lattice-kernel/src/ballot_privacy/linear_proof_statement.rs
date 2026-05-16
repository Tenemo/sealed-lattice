use serde::{Deserialize, Serialize};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    linear_proof_parameters::{LazerDemoProofEncoding, LinearProofParameterSet},
    linear_proof_transcript::shake128_32,
};

pub const LAZER_DEMO_LINEAR_SELECTED_SHORT_COLUMNS: usize = 8;
pub const LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN: usize = 4;
pub const LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW: usize = 4;
pub const LAZER_DEMO_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS: i128 = 14_960_510_030_049_216;

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
    )?;
    let encoded_statement = encode_transformed_statement(
        &transformed_statement_matrix,
        &transformed_target_vector,
        proof_encoding,
    )?;
    let arithmetic_statement_hash = shake128_32(&[&encoded_statement]);
    let public_parameters_and_statement_hash =
        shake128_32(&[public_randomness, &arithmetic_statement_hash]);

    Ok(LazerDemoLinearStatementTranscript {
        transformed_statement_matrix_rows: parameter_set.statement_rows
            * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW,
        transformed_statement_matrix_columns: LAZER_DEMO_LINEAR_SELECTED_SHORT_COLUMNS
            * LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN,
        transformed_target_vector_length: parameter_set.statement_rows
            * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW,
        encoded_statement_bytes: encoded_statement.len(),
        arithmetic_statement_hash,
        arithmetic_statement_hash_hex: to_hex(&arithmetic_statement_hash),
        public_parameters_and_statement_hash,
        public_parameters_and_statement_hash_hex: to_hex(&public_parameters_and_statement_hash),
    })
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
    if parameter_set.ring_degree
        != proof_encoding.ring_degree * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW
    {
        return Err(invalid_statement(
            "linear statement demo ring decomposition factor does not match the proof encoding",
        ));
    }
    if parameter_set.statement_columns < LAZER_DEMO_LINEAR_SELECTED_SHORT_COLUMNS {
        return Err(invalid_statement(
            "linear statement does not contain the selected short witness columns",
        ));
    }
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

fn validate_source_polynomial(
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
    let transformed_rows =
        parameter_set.statement_rows * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW;
    let transformed_columns = LAZER_DEMO_LINEAR_SELECTED_SHORT_COLUMNS
        * LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN;
    let mut transformed_entries =
        vec![vec![0_u64; proof_encoding.ring_degree]; transformed_rows * transformed_columns];

    for (source_row_index, source_row) in statement_matrix_coefficients.iter().enumerate() {
        for (selected_column_index, source_polynomial) in source_row
            .iter()
            .take(LAZER_DEMO_LINEAR_SELECTED_SHORT_COLUMNS)
            .enumerate()
        {
            let split_polynomials = split_polynomial_into_proof_ring(source_polynomial)?;
            let rotated_split_polynomials = split_polynomials
                .iter()
                .map(|polynomial| rotate_left_negacyclic_signed_polynomial(polynomial))
                .collect::<Vec<_>>();

            for output_row_offset in 0..LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW {
                for output_column_offset in
                    0..LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN
                {
                    let split_index = output_row_offset as isize - output_column_offset as isize;
                    let signed_polynomial = if split_index >= 0 {
                        &split_polynomials[usize::try_from(split_index).map_err(|_| {
                            invalid_statement("linear statement split index overflowed")
                        })?]
                    } else {
                        &rotated_split_polynomials[usize::try_from(
                            LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN as isize
                                + split_index,
                        )
                        .map_err(|_| {
                            invalid_statement("linear statement rotated split index overflowed")
                        })?]
                    };
                    let transformed_row = source_row_index
                        * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW
                        + output_row_offset;
                    let transformed_column = selected_column_index
                        * LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN
                        + output_column_offset;
                    transformed_entries
                        [transformed_row * transformed_columns + transformed_column] =
                        scale_signed_polynomial_by_source_modulus_inverse(
                            signed_polynomial,
                            proof_encoding,
                        )?;
                }
            }
        }
    }

    Ok(transformed_entries)
}

fn transform_target_vector_to_proof_ring(
    target_vector_coefficients: &[Vec<u64>],
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let transformed_length =
        parameter_set.statement_rows * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW;
    let mut transformed_entries = Vec::with_capacity(transformed_length);
    for source_polynomial in target_vector_coefficients {
        for signed_polynomial in split_polynomial_into_proof_ring(source_polynomial)? {
            transformed_entries.push(scale_signed_polynomial_by_source_modulus_inverse(
                &signed_polynomial,
                proof_encoding,
            )?);
        }
    }

    Ok(transformed_entries)
}

fn split_polynomial_into_proof_ring(source_polynomial: &[u64]) -> CanonicalResult<Vec<Vec<i128>>> {
    let source_degree = source_polynomial.len();
    if !source_degree.is_multiple_of(LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW) {
        return Err(invalid_statement(
            "linear statement source degree does not decompose evenly",
        ));
    }
    let proof_ring_degree = source_degree / LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW;
    let mut split_polynomials =
        vec![vec![0_i128; proof_ring_degree]; LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW];

    for (component_index, split_polynomial) in split_polynomials.iter_mut().enumerate() {
        for (coefficient_index, coefficient) in split_polynomial.iter_mut().enumerate() {
            *coefficient = i128::from(
                source_polynomial[LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW
                    * coefficient_index
                    + component_index],
            );
        }
    }

    Ok(split_polynomials)
}

fn rotate_left_negacyclic_signed_polynomial(polynomial: &[i128]) -> Vec<i128> {
    let mut rotated = vec![0_i128; polynomial.len()];
    if polynomial.is_empty() {
        return rotated;
    }
    rotated[0] = -polynomial[polynomial.len() - 1];
    rotated[1..polynomial.len()].copy_from_slice(&polynomial[..(polynomial.len() - 1)]);

    rotated
}

fn scale_signed_polynomial_by_source_modulus_inverse(
    signed_polynomial: &[i128],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<Vec<u64>> {
    signed_polynomial
        .iter()
        .map(|coefficient| {
            positive_mod_i128(
                coefficient
                    .checked_mul(LAZER_DEMO_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS)
                    .ok_or_else(|| {
                        invalid_statement("linear statement coefficient scaling overflowed")
                    })?,
                i128::from(proof_encoding.coefficient_modulus),
            )
        })
        .collect()
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
        LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN,
        LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW,
        derive_lazer_demo_linear_statement_transcript,
    };
    use crate::{
        ballot_privacy::linear_proof_parameters::{
            LazerDemoProofEncoding, LinearProofParameterSet,
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
            &public_randomness,
        )
        .expect("statement transcript should derive");

        assert_eq!(
            transcript.transformed_statement_matrix_rows,
            parameter_set.statement_rows * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW
        );
        assert_eq!(
            transcript.transformed_statement_matrix_columns,
            8 * LAZER_DEMO_LINEAR_PROOF_RING_COLUMNS_PER_SOURCE_COLUMN
        );
        assert_eq!(
            transcript.transformed_target_vector_length,
            parameter_set.statement_rows * LAZER_DEMO_LINEAR_PROOF_RING_ROWS_PER_SOURCE_ROW
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
}
