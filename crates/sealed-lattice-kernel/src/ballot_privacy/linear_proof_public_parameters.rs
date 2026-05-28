use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{
    linear_proof_parameters::{LinearProofEncoding, demo_linear_proof_encoding_contract},
    linear_proof_rng::sample_linear_proof_uniform_u64_values,
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
};

pub const DEFAULT_LINEAR_PROOF_RING_DEGREE: usize = 64;
#[cfg(test)]
pub const DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS: u64 = 36_028_797_018_964_597;
#[cfg(test)]
pub const DEFAULT_LINEAR_PROOF_COEFFICIENT_BIT_LENGTH: usize = 56;
pub const TBOX_SHORT_MESSAGE_LENGTH: usize = 33;

const LINEAR_PROOF_ABDLOP_COMMITMENT_KEY_DOMAIN: u32 = 0;
const LINEAR_PROOF_ABDLOP_OPENING_KEY_DOMAIN: u32 = 1;
const LINEAR_PROOF_ABDLOP_MESSAGE_KEY_DOMAIN: u32 = 2;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct AbdlopPublicParameters {
    pub commitment_key_matrix: PolynomialMatrix,
    pub opening_key_matrix: PolynomialMatrix,
    pub message_key_matrix: PolynomialMatrix,
}

pub fn derive_default_abdlop_public_parameters(
    public_randomness: &[u8; 32],
) -> CanonicalResult<AbdlopPublicParameters> {
    let proof_encoding = demo_linear_proof_encoding_contract();
    derive_abdlop_public_parameters(public_randomness, &proof_encoding)
}

pub fn derive_abdlop_public_parameters(
    public_randomness: &[u8; 32],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<AbdlopPublicParameters> {
    proof_encoding.validate()?;
    let proof_ring = PolynomialRing::new(
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
    )?;

    let commitment_key_matrix = expand_linear_proof_uniform_polynomial_matrix(
        proof_ring,
        proof_encoding.compressed_commitment_vector_length,
        proof_encoding.short_response_vector_length,
        public_randomness,
        LINEAR_PROOF_ABDLOP_COMMITMENT_KEY_DOMAIN,
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    let opening_key_matrix = expand_linear_proof_uniform_polynomial_matrix(
        proof_ring,
        proof_encoding.compressed_commitment_vector_length,
        proof_encoding.randomness_response_vector_length,
        public_randomness,
        LINEAR_PROOF_ABDLOP_OPENING_KEY_DOMAIN,
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    let message_key_matrix = expand_linear_proof_uniform_polynomial_matrix(
        proof_ring,
        proof_encoding.target_commitment_vector_length,
        proof_encoding.randomness_response_vector_length,
        public_randomness,
        LINEAR_PROOF_ABDLOP_MESSAGE_KEY_DOMAIN,
        proof_encoding.full_size_coefficient_bit_length,
    )?;

    Ok(AbdlopPublicParameters {
        commitment_key_matrix,
        opening_key_matrix,
        message_key_matrix,
    })
}

pub fn expand_linear_proof_uniform_polynomial_matrix(
    ring: PolynomialRing,
    row_count: usize,
    column_count: usize,
    public_randomness: &[u8; 32],
    matrix_domain_separator: u32,
    coefficient_bit_length: usize,
) -> CanonicalResult<PolynomialMatrix> {
    if row_count == 0 || column_count == 0 {
        return Err(invalid_public_parameters(
            "uniform matrix dimensions must be non-zero",
        ));
    }
    let entry_count = row_count
        .checked_mul(column_count)
        .ok_or_else(|| invalid_public_parameters("uniform matrix entry count overflowed"))?;
    if entry_count > u32::MAX as usize {
        return Err(invalid_public_parameters(
            "uniform matrix entry count does not fit in the proof domain layout",
        ));
    }

    let mut entries = Vec::with_capacity(entry_count);
    for entry_index in 0..entry_count {
        let entry_domain_separator = compose_linear_proof_matrix_domain(
            matrix_domain_separator,
            u32::try_from(entry_index).map_err(|_| {
                invalid_public_parameters("uniform matrix entry index does not fit in u32")
            })?,
        );
        entries.push(sample_linear_proof_uniform_u64_values(
            ring.degree(),
            ring.modulus(),
            coefficient_bit_length,
            public_randomness,
            entry_domain_separator,
        )?);
    }

    PolynomialMatrix::new(ring, row_count, column_count, entries)
}

fn compose_linear_proof_matrix_domain(matrix_domain_separator: u32, entry_index: u32) -> u64 {
    (u64::from(matrix_domain_separator) << 32) | u64::from(entry_index)
}

fn invalid_public_parameters(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS, DEFAULT_LINEAR_PROOF_RING_DEGREE,
        derive_default_abdlop_public_parameters, expand_linear_proof_uniform_polynomial_matrix,
    };
    use crate::{
        ballot_privacy::{
            linear_proof_profile_constants::DEMO_GENERATED_PARAMETER_CONTRACT,
            polynomial_ring::PolynomialRing,
        },
        hashing::to_hex,
        transcript_core::decode_hex,
    };

    fn generated_vector_case(case_name: &str) -> serde_json::Value {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        )))
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
    fn uniform_matrix_expansion_matches_upstream_statement_vector() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let public_randomness_bytes = decode_hex(
            vector_case["publicRandomnessHex"]
                .as_str()
                .expect("public randomness should be present"),
        )
        .expect("public randomness should decode");
        let mut public_randomness = [0_u8; 32];
        public_randomness.copy_from_slice(&public_randomness_bytes);
        let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> =
            serde_json::from_value(vector_case["statementMatrixCoefficients"].clone())
                .expect("statement matrix should deserialize");
        let source_ring = PolynomialRing::new(
            DEMO_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
            DEMO_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus,
        )
        .expect("ring should validate");

        let expanded_statement_matrix = expand_linear_proof_uniform_polynomial_matrix(
            source_ring,
            DEMO_GENERATED_PARAMETER_CONTRACT.statement_rows,
            DEMO_GENERATED_PARAMETER_CONTRACT.statement_columns,
            &public_randomness,
            0,
            32,
        )
        .expect("statement matrix expansion should succeed");

        assert_eq!(
            expanded_statement_matrix.entries_by_row(),
            statement_matrix_coefficients
        );
    }

    #[test]
    fn abdlop_public_parameter_expansion_has_demo_shapes() {
        let public_randomness = [0_u8; 32];

        let public_parameters = derive_default_abdlop_public_parameters(&public_randomness)
            .expect("public parameters should expand");

        assert_eq!(public_parameters.commitment_key_matrix.rows(), 13);
        assert_eq!(public_parameters.commitment_key_matrix.columns(), 33);
        assert_eq!(public_parameters.opening_key_matrix.rows(), 13);
        assert_eq!(public_parameters.opening_key_matrix.columns(), 47);
        assert_eq!(public_parameters.message_key_matrix.rows(), 12);
        assert_eq!(public_parameters.message_key_matrix.columns(), 47);
        assert_eq!(
            public_parameters.commitment_key_matrix.ring().degree(),
            DEFAULT_LINEAR_PROOF_RING_DEGREE
        );
        assert_eq!(
            public_parameters.commitment_key_matrix.ring().modulus(),
            DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS
        );
    }

    #[test]
    fn abdlop_public_parameter_expansion_binds_public_randomness() {
        let zero_randomness = [0_u8; 32];
        let mut changed_randomness = [0_u8; 32];
        changed_randomness[0] = 1;

        let zero_parameters = derive_default_abdlop_public_parameters(&zero_randomness)
            .expect("zero public parameters should expand");
        let changed_parameters = derive_default_abdlop_public_parameters(&changed_randomness)
            .expect("changed public parameters should expand");

        let zero_first_entry = zero_parameters
            .commitment_key_matrix
            .entry(0, 0)
            .expect("first entry should exist");
        let changed_first_entry = changed_parameters
            .commitment_key_matrix
            .entry(0, 0)
            .expect("first entry should exist");
        assert_ne!(
            to_hex(&u64_slice_to_bytes(zero_first_entry)),
            to_hex(&u64_slice_to_bytes(changed_first_entry))
        );
    }

    fn u64_slice_to_bytes(values: &[u64]) -> Vec<u8> {
        values
            .iter()
            .flat_map(|value| value.to_le_bytes())
            .collect()
    }
}
