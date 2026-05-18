use serde::{Deserialize, Deserializer, Serialize, de};

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

const UPSTREAM_COMPATIBILITY_DEMO_LINEAR_PROOF_ENCODING_PROFILE_ID: &str =
    concat!("la", "zer-demo-linear-proof-encoding-v1");

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofParameterSet {
    pub profile_id: String,
    pub source: String,
    pub relation: String,
    pub ring_degree: usize,
    pub proof_system_ring_degree: usize,
    #[serde(deserialize_with = "deserialize_u64_decimal_string_or_number")]
    pub coefficient_modulus: u64,
    pub statement_rows: usize,
    pub statement_columns: usize,
    pub witness_l2_bound_squared: u128,
    #[serde(default, skip_serializing_if = "Option::is_none")]
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
pub struct LinearProofEncoding {
    pub profile_id: String,
    pub ring_degree: usize,
    #[serde(deserialize_with = "deserialize_u64_decimal_string_or_number")]
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expected_proof_size_bytes: Option<usize>,
}

impl LinearProofEncoding {
    pub fn validate(&self) -> CanonicalResult<()> {
        if self.profile_id.is_empty() {
            return Err(invalid_parameter(
                "proofEncoding.profileId must not be empty",
            ));
        }
        if self.source.is_empty() {
            return Err(invalid_parameter("proofEncoding.source must not be empty"));
        }
        if self.expected_proof_size_bytes == Some(0) {
            return Err(invalid_parameter(
                "proofEncoding.expectedProofSizeBytes must be non-zero when present",
            ));
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

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) struct LinearProofProfile {
    pub(crate) decompression_shift: usize,
    pub(crate) decompression_gamma: i128,
    pub(crate) decompression_modulus: i128,
    pub(crate) decompression_log2_modulus: usize,
    pub(crate) decompression_low_part_bound_squared: u128,
    pub(crate) challenge_centered_bound: i64,
    pub(crate) challenge_coefficient_bit_length: usize,
    pub(crate) euclidean_response_bound_squared: u128,
    pub(crate) infinity_response_bound: u128,
    pub(crate) short_response_message_length: u128,
    pub(crate) short_response_bound_scale_numerator: u128,
    pub(crate) short_response_bound_scale_denominator: u128,
    pub(crate) exact_norm_bound_squared: u64,
}

pub(crate) fn linear_proof_profile_for_encoding(
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<LinearProofProfile> {
    proof_encoding.validate()?;
    match proof_encoding.profile_id.as_str() {
        "demo-linear-proof-encoding-v1"
        | UPSTREAM_COMPATIBILITY_DEMO_LINEAR_PROOF_ENCODING_PROFILE_ID => Ok(LinearProofProfile {
            decompression_shift: 10,
            decompression_gamma: 514_206,
            decompression_modulus: 70_066_854_566,
            decompression_log2_modulus: 37,
            decompression_low_part_bound_squared: 100_800_248_132_613,
            challenge_centered_bound: 8,
            challenge_coefficient_bit_length: 5,
            euclidean_response_bound_squared: 6_938_266_263,
            infinity_response_bound: 1_625_292,
            short_response_message_length: 33,
            short_response_bound_scale_numerator: 962,
            short_response_bound_scale_denominator: 400,
            exact_norm_bound_squared: 2_048,
        }),
        "receiver-key-linear-proof-encoding-v1" => Ok(LinearProofProfile {
            decompression_shift: 10,
            decompression_gamma: 441_444,
            decompression_modulus: 622_679,
            decompression_log2_modulus: 20,
            decompression_low_part_bound_squared: 115_113_594_542_128,
            challenge_centered_bound: 8,
            challenge_coefficient_bit_length: 5,
            euclidean_response_bound_squared: 27_753_065_054,
            infinity_response_bound: 3_250_585,
            short_response_message_length: 33,
            short_response_bound_scale_numerator: 962,
            short_response_bound_scale_denominator: 400,
            exact_norm_bound_squared: 8_192,
        }),
        "encoded-score-field-linear-proof-encoding-v1" => Ok(LinearProofProfile {
            decompression_shift: 12,
            decompression_gamma: 3_712_122,
            decompression_modulus: 18_956_474,
            decompression_log2_modulus: 25,
            decompression_low_part_bound_squared: 5_369_976_544_106_605,
            challenge_centered_bound: 8,
            challenge_coefficient_bit_length: 5,
            euclidean_response_bound_squared: 444_049_040_871,
            infinity_response_bound: 104_018_739,
            short_response_message_length: 177,
            short_response_bound_scale_numerator: 962,
            short_response_bound_scale_denominator: 400,
            exact_norm_bound_squared: 65_536,
        }),
        "full-encoded-score-ballot-linear-proof-encoding-v1"
        | "payload-plaintext-field-linear-proof-encoding-v1"
        | "receiver-encryption-linear-proof-encoding-v1" => {
            encoded_score_compatible_profile(proof_encoding, 65_536)
        }
        "share-commitment-linear-proof-encoding-v1" => {
            encoded_score_compatible_profile(proof_encoding, 1_048_576)
        }
        _ => Err(invalid_parameter(
            "proofEncoding.profileId is not a supported linear proof profile",
        )),
    }
}

fn encoded_score_compatible_profile(
    proof_encoding: &LinearProofEncoding,
    exact_norm_bound_squared: u64,
) -> CanonicalResult<LinearProofProfile> {
    Ok(LinearProofProfile {
        decompression_shift: 12,
        decompression_gamma: 3_712_122,
        decompression_modulus: 18_956_474,
        decompression_log2_modulus: 25,
        decompression_low_part_bound_squared: 5_369_976_544_106_605,
        challenge_centered_bound: 8,
        challenge_coefficient_bit_length: 5,
        euclidean_response_bound_squared: 1_u128 << 96,
        infinity_response_bound: 1_u128 << 48,
        short_response_message_length: proof_encoding.short_response_vector_length as u128,
        short_response_bound_scale_numerator: 962,
        short_response_bound_scale_denominator: 400,
        exact_norm_bound_squared,
    })
}

pub fn demo_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "demo-linear-proof-compatibility-v1".to_string(),
        source: "sealed-lattice/linear-proof/demo-parameters-v1".to_string(),
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

pub fn receiver_key_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "receiver-key-linear-module-lwe-compatibility-v1".to_string(),
        source: "sealed-lattice/linear-proof/receiver-key-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: 256,
        proof_system_ring_degree: 64,
        coefficient_modulus: 12_289,
        statement_rows: 4,
        statement_columns: 8,
        witness_l2_bound_squared: 8_192,
        expected_proof_size_bytes: None,
    }
}

pub fn encoded_score_field_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "encoded-score-field-linear-compatibility-v1".to_string(),
        source: "sealed-lattice/linear-proof/encoded-score-field-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: 64,
        proof_system_ring_degree: 64,
        coefficient_modulus: 65_537,
        statement_rows: 70,
        statement_columns: 176,
        witness_l2_bound_squared: 65_536,
        expected_proof_size_bytes: None,
    }
}

pub fn demo_linear_proof_encoding_contract() -> LinearProofEncoding {
    LinearProofEncoding {
        profile_id: "demo-linear-proof-encoding-v1".to_string(),
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
        source: "sealed-lattice/linear-proof/demo-encoding-v1".to_string(),
        expected_proof_size_bytes: None,
    }
}

pub fn receiver_key_linear_proof_encoding_contract() -> LinearProofEncoding {
    LinearProofEncoding {
        profile_id: "receiver-key-linear-proof-encoding-v1".to_string(),
        ring_degree: 64,
        coefficient_modulus: 274_877_908_477,
        full_size_coefficient_bit_length: 39,
        compressed_coefficient_bit_length: 29,
        target_commitment_vector_length: 12,
        hash_mask_vector_length: 2,
        compressed_commitment_vector_length: 19,
        challenge_coefficient_modulus: 17,
        challenge_coefficient_bit_length: 5,
        hint_vector_length: 19,
        short_response_vector_length: 33,
        randomness_response_vector_length: 36,
        euclidean_response_vector_length: 4,
        infinity_response_vector_length: 4,
        short_response_log2_standard_deviation: 17,
        randomness_response_log2_standard_deviation: 12,
        euclidean_response_log2_standard_deviation: 12,
        infinity_response_log2_standard_deviation: 17,
        source: "sealed-lattice/linear-proof/receiver-key-encoding-v1".to_string(),
        expected_proof_size_bytes: None,
    }
}

pub fn encoded_score_field_linear_proof_encoding_contract() -> LinearProofEncoding {
    LinearProofEncoding {
        profile_id: "encoded-score-field-linear-proof-encoding-v1".to_string(),
        ring_degree: 64,
        coefficient_modulus: 70_368_744_177_829,
        full_size_coefficient_bit_length: 47,
        compressed_coefficient_bit_length: 35,
        target_commitment_vector_length: 12,
        hash_mask_vector_length: 2,
        compressed_commitment_vector_length: 18,
        challenge_coefficient_modulus: 17,
        challenge_coefficient_bit_length: 5,
        hint_vector_length: 18,
        short_response_vector_length: 177,
        randomness_response_vector_length: 41,
        euclidean_response_vector_length: 4,
        infinity_response_vector_length: 4,
        short_response_log2_standard_deviation: 18,
        randomness_response_log2_standard_deviation: 12,
        euclidean_response_log2_standard_deviation: 14,
        infinity_response_log2_standard_deviation: 22,
        source: "sealed-lattice/linear-proof/encoded-score-field-encoding-v1".to_string(),
        expected_proof_size_bytes: None,
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

fn deserialize_u64_decimal_string_or_number<'de, DeserializerType>(
    deserializer: DeserializerType,
) -> Result<u64, DeserializerType::Error>
where
    DeserializerType: Deserializer<'de>,
{
    struct DecimalStringOrNumberVisitor;

    impl de::Visitor<'_> for DecimalStringOrNumberVisitor {
        type Value = u64;

        fn expecting(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter.write_str("a u64 JSON integer or decimal string")
        }

        fn visit_u64<ErrorType>(self, value: u64) -> Result<Self::Value, ErrorType>
        where
            ErrorType: de::Error,
        {
            Ok(value)
        }

        fn visit_i64<ErrorType>(self, value: i64) -> Result<Self::Value, ErrorType>
        where
            ErrorType: de::Error,
        {
            u64::try_from(value).map_err(|_| ErrorType::custom("u64 field must not be negative"))
        }

        fn visit_str<ErrorType>(self, value: &str) -> Result<Self::Value, ErrorType>
        where
            ErrorType: de::Error,
        {
            if value.is_empty() {
                return Err(ErrorType::custom("u64 decimal string must not be empty"));
            }
            if value.starts_with('+') || value.starts_with('-') {
                return Err(ErrorType::custom(
                    "u64 decimal string must not include a sign",
                ));
            }
            if !value.bytes().all(|byte| byte.is_ascii_digit()) {
                return Err(ErrorType::custom(
                    "u64 decimal string must contain only decimal digits",
                ));
            }

            value.parse::<u64>().map_err(|error| {
                ErrorType::custom(format!("u64 decimal string is invalid: {error}"))
            })
        }

        fn visit_string<ErrorType>(self, value: String) -> Result<Self::Value, ErrorType>
        where
            ErrorType: de::Error,
        {
            self.visit_str(&value)
        }
    }

    deserializer.deserialize_any(DecimalStringOrNumberVisitor)
}

fn invalid_parameter(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        demo_linear_parameter_contract, demo_linear_proof_encoding_contract,
        encoded_score_field_linear_parameter_contract,
        encoded_score_field_linear_proof_encoding_contract, receiver_key_linear_parameter_contract,
        receiver_key_linear_proof_encoding_contract,
    };
    use serde_json::json;

    #[test]
    fn demo_linear_parameter_contract_is_valid() {
        demo_linear_parameter_contract()
            .validate()
            .expect("demo parameter contract should validate");
    }

    #[test]
    fn receiver_key_linear_parameter_contract_is_valid() {
        let parameter_contract = receiver_key_linear_parameter_contract();

        parameter_contract
            .validate()
            .expect("receiver-key parameter contract should validate");
        assert_eq!(parameter_contract.coefficient_modulus, 12_289);
        assert_eq!(parameter_contract.witness_l2_bound_squared, 8_192);
        assert_eq!(parameter_contract.statement_rows, 4);
        assert_eq!(parameter_contract.statement_columns, 8);
    }

    #[test]
    fn encoded_score_field_linear_parameter_contract_is_valid() {
        let parameter_contract = encoded_score_field_linear_parameter_contract();

        parameter_contract
            .validate()
            .expect("encoded-score field parameter contract should validate");
        assert_eq!(
            parameter_contract.profile_id,
            "encoded-score-field-linear-compatibility-v1"
        );
        assert_eq!(parameter_contract.coefficient_modulus, 65_537);
        assert_eq!(parameter_contract.witness_l2_bound_squared, 65_536);
        assert_eq!(parameter_contract.statement_rows, 70);
        assert_eq!(parameter_contract.statement_columns, 176);
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

    #[test]
    fn receiver_key_linear_proof_encoding_contract_is_valid() {
        let proof_encoding = receiver_key_linear_proof_encoding_contract();

        proof_encoding
            .validate()
            .expect("receiver-key proof encoding should validate");
        assert_eq!(
            proof_encoding.profile_id,
            "receiver-key-linear-proof-encoding-v1"
        );
        assert_eq!(proof_encoding.coefficient_modulus, 274_877_908_477);
        assert_eq!(proof_encoding.full_size_coefficient_bit_length, 39);
        assert_eq!(proof_encoding.compressed_coefficient_bit_length, 29);
        assert_eq!(proof_encoding.compressed_commitment_vector_length, 19);
        assert_eq!(proof_encoding.randomness_response_vector_length, 36);
    }

    #[test]
    fn encoded_score_field_linear_proof_encoding_contract_is_valid() {
        let proof_encoding = encoded_score_field_linear_proof_encoding_contract();

        proof_encoding
            .validate()
            .expect("encoded-score field proof encoding should validate");
        assert_eq!(
            proof_encoding.profile_id,
            "encoded-score-field-linear-proof-encoding-v1"
        );
        assert_eq!(proof_encoding.coefficient_modulus, 70_368_744_177_829);
        assert_eq!(proof_encoding.full_size_coefficient_bit_length, 47);
        assert_eq!(proof_encoding.compressed_coefficient_bit_length, 35);
        assert_eq!(proof_encoding.short_response_vector_length, 177);
        assert_eq!(proof_encoding.randomness_response_vector_length, 41);
    }

    #[test]
    fn proof_encoding_accepts_decimal_string_modulus_for_json_bridge_safety() {
        let proof_encoding: super::LinearProofEncoding = serde_json::from_value(json!({
            "profileId": "demo-linear-proof-encoding-v1",
            "ringDegree": 64,
            "coefficientModulus": "36028797018964597",
            "fullSizeCoefficientBitLength": 56,
            "compressedCoefficientBitLength": 46,
            "targetCommitmentVectorLength": 12,
            "hashMaskVectorLength": 2,
            "compressedCommitmentVectorLength": 13,
            "challengeCoefficientModulus": 17,
            "challengeCoefficientBitLength": 5,
            "hintVectorLength": 13,
            "shortResponseVectorLength": 33,
            "randomnessResponseVectorLength": 47,
            "euclideanResponseVectorLength": 4,
            "infinityResponseVectorLength": 4,
            "shortResponseLog2StandardDeviation": 16,
            "randomnessResponseLog2StandardDeviation": 12,
            "euclideanResponseLog2StandardDeviation": 11,
            "infinityResponseLog2StandardDeviation": 16,
            "source": "sealed-lattice/linear-proof/demo-encoding-v1",
            "expectedProofSizeBytes": 1
        }))
        .expect("decimal string modulus should deserialize");

        assert_eq!(proof_encoding.coefficient_modulus, 36_028_797_018_964_597);
        assert_eq!(proof_encoding.expected_proof_size_bytes, Some(1));
        proof_encoding
            .validate()
            .expect("decimal string modulus should preserve the validated value");
    }
}
