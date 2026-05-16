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

fn invalid_parameter(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::demo_linear_parameter_contract;

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
}
