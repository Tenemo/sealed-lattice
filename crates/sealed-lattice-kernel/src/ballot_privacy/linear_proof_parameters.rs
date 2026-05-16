use serde::{Deserialize, Serialize};

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofParameterSet {
    pub profile_id: String,
    pub source: String,
    pub relation: String,
    pub ring_degree: usize,
    pub proof_system_ring_degree: usize,
    pub coefficient_modulus: u64,
    pub statement_rows: usize,
    pub statement_columns: usize,
    pub witness_l2_bound_squared: u128,
    pub expected_proof_size_bytes: Option<usize>,
}

impl LinearProofParameterSet {
    pub fn validate(&self) -> CanonicalResult<()> {
        if self.profile_id.is_empty() {
            return Err(invalid_parameter("profileId must not be empty"));
        }
        if self.source.is_empty() {
            return Err(invalid_parameter("source must not be empty"));
        }
        if self.relation != "A*w + t = 0" {
            return Err(invalid_parameter(
                "relation must be the frozen linear proof target",
            ));
        }
        if self.ring_degree == 0 || !self.ring_degree.is_power_of_two() {
            return Err(invalid_parameter(
                "ringDegree must be a non-zero power of two",
            ));
        }
        if self.proof_system_ring_degree == 0
            || !self.proof_system_ring_degree.is_power_of_two()
            || !self
                .ring_degree
                .is_multiple_of(self.proof_system_ring_degree)
        {
            return Err(invalid_parameter(
                "proofSystemRingDegree must be a non-zero power of two dividing ringDegree",
            ));
        }
        if self.coefficient_modulus < 2 {
            return Err(invalid_parameter("coefficientModulus must be at least two"));
        }
        if self.statement_rows == 0 || self.statement_columns == 0 {
            return Err(invalid_parameter("statement dimensions must be non-zero"));
        }
        if self.witness_l2_bound_squared == 0 {
            return Err(invalid_parameter("witnessL2BoundSquared must be non-zero"));
        }
        if self.expected_proof_size_bytes == Some(0) {
            return Err(invalid_parameter(
                "expectedProofSizeBytes must be non-zero when present",
            ));
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LazerDemoProofEncoding {
    pub profile_id: String,
    pub ring_degree: usize,
    pub coefficient_modulus: u64,
    pub full_size_coefficient_bit_length: usize,
    pub compressed_coefficient_bit_length: usize,
    pub target_commitment_vector_length: usize,
    pub hash_mask_vector_length: usize,
    pub compressed_commitment_vector_length: usize,
    pub challenge_coefficient_modulus: u64,
    pub challenge_coefficient_bit_length: usize,
    pub hint_vector_length: usize,
    pub short_response_vector_length: usize,
    pub randomness_response_vector_length: usize,
    pub euclidean_response_vector_length: usize,
    pub infinity_response_vector_length: usize,
    pub short_response_log2_standard_deviation: usize,
    pub randomness_response_log2_standard_deviation: usize,
    pub euclidean_response_log2_standard_deviation: usize,
    pub infinity_response_log2_standard_deviation: usize,
    pub source: String,
}

impl LazerDemoProofEncoding {
    pub fn validate(&self) -> CanonicalResult<()> {
        if self.profile_id.is_empty() {
            return Err(invalid_parameter(
                "proofEncoding.profileId must not be empty",
            ));
        }
        if self.source.is_empty() {
            return Err(invalid_parameter("proofEncoding.source must not be empty"));
        }
        if self.ring_degree == 0 || !self.ring_degree.is_power_of_two() {
            return Err(invalid_parameter(
                "proofEncoding.ringDegree must be a non-zero power of two",
            ));
        }
        if self.coefficient_modulus < 2 || self.challenge_coefficient_modulus < 2 {
            return Err(invalid_parameter(
                "proofEncoding moduli must be at least two",
            ));
        }
        validate_bit_length(
            self.full_size_coefficient_bit_length,
            "proofEncoding.fullSizeCoefficientBitLength",
        )?;
        validate_bit_length(
            self.compressed_coefficient_bit_length,
            "proofEncoding.compressedCoefficientBitLength",
        )?;
        validate_bit_length(
            self.challenge_coefficient_bit_length,
            "proofEncoding.challengeCoefficientBitLength",
        )?;
        if self.compressed_coefficient_bit_length >= self.full_size_coefficient_bit_length {
            return Err(invalid_parameter(
                "proofEncoding.compressedCoefficientBitLength must be smaller than proofEncoding.fullSizeCoefficientBitLength",
            ));
        }
        if self.coefficient_modulus > bit_capacity(self.full_size_coefficient_bit_length)? {
            return Err(invalid_parameter(
                "proofEncoding.coefficientModulus does not fit in proofEncoding.fullSizeCoefficientBitLength",
            ));
        }
        if self.challenge_coefficient_modulus > bit_capacity(self.challenge_coefficient_bit_length)?
        {
            return Err(invalid_parameter(
                "proofEncoding.challengeCoefficientModulus does not fit in proofEncoding.challengeCoefficientBitLength",
            ));
        }
        for (field_name, value) in [
            (
                "proofEncoding.targetCommitmentVectorLength",
                self.target_commitment_vector_length,
            ),
            (
                "proofEncoding.hashMaskVectorLength",
                self.hash_mask_vector_length,
            ),
            (
                "proofEncoding.compressedCommitmentVectorLength",
                self.compressed_commitment_vector_length,
            ),
            ("proofEncoding.hintVectorLength", self.hint_vector_length),
            (
                "proofEncoding.shortResponseVectorLength",
                self.short_response_vector_length,
            ),
            (
                "proofEncoding.randomnessResponseVectorLength",
                self.randomness_response_vector_length,
            ),
        ] {
            if value == 0 {
                return Err(invalid_parameter(format!("{field_name} must be non-zero")));
            }
        }

        Ok(())
    }
}

pub fn demo_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "lazer-linear-demo-compatibility-v1".to_string(),
        source: "temp/lazer/python/demo/demo_params.h".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: 256,
        proof_system_ring_degree: 64,
        coefficient_modulus: 4_294_962_689,
        statement_rows: 4,
        statement_columns: 8,
        witness_l2_bound_squared: 2_048,
        expected_proof_size_bytes: None,
    }
}

pub fn demo_linear_proof_encoding_contract() -> LazerDemoProofEncoding {
    LazerDemoProofEncoding {
        profile_id: "lazer-demo-linear-proof-encoding-v1".to_string(),
        ring_degree: 64,
        coefficient_modulus: 36_028_797_018_964_597,
        full_size_coefficient_bit_length: 56,
        compressed_coefficient_bit_length: 46,
        target_commitment_vector_length: 12,
        hash_mask_vector_length: 2,
        compressed_commitment_vector_length: 13,
        challenge_coefficient_modulus: 17,
        challenge_coefficient_bit_length: 5,
        hint_vector_length: 13,
        short_response_vector_length: 33,
        randomness_response_vector_length: 47,
        euclidean_response_vector_length: 4,
        infinity_response_vector_length: 4,
        short_response_log2_standard_deviation: 16,
        randomness_response_log2_standard_deviation: 12,
        euclidean_response_log2_standard_deviation: 11,
        infinity_response_log2_standard_deviation: 16,
        source: "temp/lazer/python/demo/demo_params.h:_param".to_string(),
    }
}

fn validate_bit_length(bit_length: usize, field_name: &str) -> CanonicalResult<()> {
    if bit_length == 0 || bit_length > 63 {
        return Err(invalid_parameter(format!(
            "{field_name} must be between one and sixty-three"
        )));
    }

    Ok(())
}

fn bit_capacity(bit_length: usize) -> CanonicalResult<u64> {
    validate_bit_length(bit_length, "bitLength")?;
    Ok(1_u64 << bit_length)
}

fn invalid_parameter(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{demo_linear_parameter_contract, demo_linear_proof_encoding_contract};

    #[test]
    fn demo_linear_parameter_contract_is_valid() {
        demo_linear_parameter_contract()
            .validate()
            .expect("demo parameter contract should validate");
    }

    #[test]
    fn rejects_invalid_parameter_shapes() {
        let mut parameters = demo_linear_parameter_contract();
        parameters.proof_system_ring_degree = 63;

        let error = parameters
            .validate()
            .expect_err("non-power-of-two proof ring should fail");

        assert!(error.message.contains("proofSystemRingDegree"));
    }

    #[test]
    fn demo_linear_proof_encoding_contract_is_valid() {
        demo_linear_proof_encoding_contract()
            .validate()
            .expect("demo proof encoding should validate");
    }
}
