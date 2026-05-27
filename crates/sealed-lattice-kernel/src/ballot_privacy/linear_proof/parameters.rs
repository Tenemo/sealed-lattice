use serde::{Deserialize, Deserializer, Serialize, de};

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::profile_constants::{
    AGGREGATE_DERIVATION_COMPONENT_EXACT_NORM_BOUND_SQUARED, DEMO_GENERATED_PROFILE,
    ENCODED_SCORE_FIELD_GENERATED_PROFILE, GENERATED_COMPONENT_EUCLIDEAN_RESPONSE_BOUND_SQUARED,
    GENERATED_COMPONENT_INFINITY_RESPONSE_BOUND,
    GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED,
    GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED,
    GeneratedLinearProofProfileConstants, RECEIVER_KEY_GENERATED_PROFILE,
};
#[cfg(test)]
use super::profile_constants::{
    DEMO_GENERATED_PARAMETER_CONTRACT, ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT,
    RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT,
};

const UPSTREAM_COMPATIBILITY_DEMO_LINEAR_PROOF_ENCODING_PROFILE_ID: &str =
    "lazer-demo-linear-proof-encoding-v1";

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
            (
                "proofEncoding.euclideanResponseVectorLength",
                self.euclidean_response_vector_length,
            ),
            (
                "proofEncoding.infinityResponseVectorLength",
                self.infinity_response_vector_length,
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
    let proof_profile = match proof_encoding.profile_id.as_str() {
        "demo-linear-proof-encoding-v1"
        | UPSTREAM_COMPATIBILITY_DEMO_LINEAR_PROOF_ENCODING_PROFILE_ID => {
            profile_from_generated_constants(DEMO_GENERATED_PROFILE)
        }
        "receiver-key-linear-proof-encoding-v1" => {
            profile_from_generated_constants(RECEIVER_KEY_GENERATED_PROFILE)
        }
        "encoded-score-field-linear-proof-encoding-v1" => {
            profile_from_generated_constants(ENCODED_SCORE_FIELD_GENERATED_PROFILE)
        }
        "full-encoded-score-ballot-linear-proof-encoding-v1"
        | "payload-plaintext-field-linear-proof-encoding-v1"
        | "receiver-encryption-linear-proof-encoding-v1" => encoded_score_compatible_profile(
            proof_encoding,
            GENERATED_FIELD_COMPONENT_EXACT_NORM_BOUND_SQUARED,
        )?,
        "share-commitment-linear-proof-encoding-v1" => encoded_score_compatible_profile(
            proof_encoding,
            GENERATED_SHARE_COMMITMENT_COMPONENT_EXACT_NORM_BOUND_SQUARED,
        )?,
        "aggregate-derivation-linear-proof-encoding-v1" => encoded_score_compatible_profile(
            proof_encoding,
            AGGREGATE_DERIVATION_COMPONENT_EXACT_NORM_BOUND_SQUARED,
        )?,
        _ => {
            return Err(unknown_proof_profile(
                "proofEncoding.profileId is not a supported linear proof profile",
            ));
        }
    };

    validate_linear_proof_profile_invariants(proof_profile)
}

pub(crate) fn linear_proof_claim_boundary_status_labels(
    proof_encoding: &LinearProofEncoding,
) -> Vec<&'static str> {
    match proof_encoding.profile_id.as_str() {
        "full-encoded-score-ballot-linear-proof-encoding-v1"
        | "payload-plaintext-field-linear-proof-encoding-v1"
        | "receiver-encryption-linear-proof-encoding-v1"
        | "share-commitment-linear-proof-encoding-v1"
        | "aggregate-derivation-linear-proof-encoding-v1" => vec![
            "LinearProofCompatibilityBoundsOnly",
            "LinearProofStandaloneSoundnessEvidenceMissing",
        ],
        _ => Vec::new(),
    }
}

fn profile_from_generated_constants(
    constants: GeneratedLinearProofProfileConstants,
) -> LinearProofProfile {
    LinearProofProfile {
        decompression_shift: constants.decompression_shift,
        decompression_gamma: constants.decompression_gamma,
        decompression_modulus: constants.decompression_modulus,
        decompression_log2_modulus: constants.decompression_log2_modulus,
        decompression_low_part_bound_squared: constants.decompression_low_part_bound_squared,
        challenge_centered_bound: constants.challenge_centered_bound,
        challenge_coefficient_bit_length: constants.challenge_coefficient_bit_length,
        euclidean_response_bound_squared: constants.euclidean_response_bound_squared,
        infinity_response_bound: constants.infinity_response_bound,
        short_response_message_length: constants.short_response_message_length,
        short_response_bound_scale_numerator: constants.short_response_bound_scale_numerator,
        short_response_bound_scale_denominator: constants.short_response_bound_scale_denominator,
        exact_norm_bound_squared: constants.exact_norm_bound_squared,
    }
}

fn validate_linear_proof_profile_invariants(
    proof_profile: LinearProofProfile,
) -> CanonicalResult<LinearProofProfile> {
    if proof_profile.decompression_gamma <= 0 {
        return Err(invalid_parameter(
            "linear proof decompression gamma must be positive",
        ));
    }
    if proof_profile.decompression_modulus <= proof_profile.decompression_gamma {
        return Err(invalid_parameter(
            "linear proof decompression modulus must be larger than gamma",
        ));
    }
    if proof_profile.decompression_log2_modulus == 0 {
        return Err(invalid_parameter(
            "linear proof decompression modulus bit length must be non-zero",
        ));
    }
    let decompression_log2_modulus = u32::try_from(proof_profile.decompression_log2_modulus)
        .map_err(|_| {
            invalid_parameter("linear proof decompression modulus bit length is too large")
        })?;
    let decompression_modulus_capacity = 1_i128
        .checked_shl(decompression_log2_modulus)
        .ok_or_else(|| {
            invalid_parameter("linear proof decompression modulus bit length overflowed")
        })?;
    let previous_decompression_modulus_capacity = 1_i128
        .checked_shl(decompression_log2_modulus - 1)
        .ok_or_else(|| {
            invalid_parameter("linear proof decompression modulus bit length overflowed")
        })?;
    if proof_profile.decompression_modulus > decompression_modulus_capacity
        || proof_profile.decompression_modulus <= previous_decompression_modulus_capacity
    {
        return Err(invalid_parameter(
            "linear proof decompression modulus must match the rounded-up bit length",
        ));
    }
    if proof_profile.decompression_low_part_bound_squared == 0 {
        return Err(invalid_parameter(
            "linear proof decompression low-part bound must be non-zero",
        ));
    }
    if proof_profile.challenge_centered_bound <= 0
        || proof_profile.challenge_coefficient_bit_length == 0
    {
        return Err(invalid_parameter(
            "linear proof challenge profile bounds must be non-zero",
        ));
    }
    if proof_profile.euclidean_response_bound_squared == 0
        || proof_profile.infinity_response_bound == 0
        || proof_profile.short_response_message_length == 0
        || proof_profile.short_response_bound_scale_numerator == 0
        || proof_profile.short_response_bound_scale_denominator == 0
        || proof_profile.exact_norm_bound_squared == 0
    {
        return Err(invalid_parameter(
            "linear proof response and norm profile bounds must be non-zero",
        ));
    }

    Ok(proof_profile)
}

fn encoded_score_compatible_profile(
    proof_encoding: &LinearProofEncoding,
    exact_norm_bound_squared: u64,
) -> CanonicalResult<LinearProofProfile> {
    let generated_profile = ENCODED_SCORE_FIELD_GENERATED_PROFILE;
    Ok(LinearProofProfile {
        decompression_shift: generated_profile.decompression_shift,
        decompression_gamma: generated_profile.decompression_gamma,
        decompression_modulus: generated_profile.decompression_modulus,
        decompression_log2_modulus: generated_profile.decompression_log2_modulus,
        decompression_low_part_bound_squared: generated_profile
            .decompression_low_part_bound_squared,
        challenge_centered_bound: generated_profile.challenge_centered_bound,
        challenge_coefficient_bit_length: generated_profile.challenge_coefficient_bit_length,
        euclidean_response_bound_squared: GENERATED_COMPONENT_EUCLIDEAN_RESPONSE_BOUND_SQUARED,
        infinity_response_bound: GENERATED_COMPONENT_INFINITY_RESPONSE_BOUND,
        short_response_message_length: proof_encoding.short_response_vector_length as u128,
        short_response_bound_scale_numerator: generated_profile
            .short_response_bound_scale_numerator,
        short_response_bound_scale_denominator: generated_profile
            .short_response_bound_scale_denominator,
        exact_norm_bound_squared,
    })
}

#[cfg(test)]
pub fn demo_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "demo-linear-proof-compatibility-v1".to_string(),
        source: "sealed-lattice/linear-proof/demo-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: DEMO_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
        proof_system_ring_degree: DEMO_GENERATED_PARAMETER_CONTRACT.proof_system_ring_degree,
        coefficient_modulus: DEMO_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus,
        statement_rows: DEMO_GENERATED_PARAMETER_CONTRACT.statement_rows,
        statement_columns: DEMO_GENERATED_PARAMETER_CONTRACT.statement_columns,
        witness_l2_bound_squared: DEMO_GENERATED_PROFILE.exact_norm_bound_squared as u128,
        expected_proof_size_bytes: None,
    }
}

#[cfg(test)]
pub fn receiver_key_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "receiver-key-linear-module-lwe-v1".to_string(),
        source: "sealed-lattice/linear-proof/receiver-key-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
        proof_system_ring_degree: RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT
            .proof_system_ring_degree,
        coefficient_modulus: RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus,
        statement_rows: RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.statement_rows,
        statement_columns: RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.statement_columns,
        witness_l2_bound_squared: RECEIVER_KEY_GENERATED_PROFILE.exact_norm_bound_squared as u128,
        expected_proof_size_bytes: None,
    }
}

#[cfg(test)]
pub fn encoded_score_field_linear_parameter_contract() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "encoded-score-field-linear-compatibility-v1".to_string(),
        source: "sealed-lattice/linear-proof/encoded-score-field-parameters-v1".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.source_ring_degree,
        proof_system_ring_degree: ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT
            .proof_system_ring_degree,
        coefficient_modulus: ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT
            .source_coefficient_modulus,
        statement_rows: ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.statement_rows,
        statement_columns: ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.statement_columns,
        witness_l2_bound_squared: ENCODED_SCORE_FIELD_GENERATED_PROFILE.exact_norm_bound_squared
            as u128,
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

#[cfg(test)]
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

#[cfg(test)]
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

fn unknown_proof_profile(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::UnknownProofProfile, message)
}

#[cfg(test)]
mod tests {
    use super::{
        demo_linear_parameter_contract, demo_linear_proof_encoding_contract,
        encoded_score_field_linear_parameter_contract,
        encoded_score_field_linear_proof_encoding_contract, linear_proof_profile_for_encoding,
        profile_from_generated_constants, receiver_key_linear_parameter_contract,
        receiver_key_linear_proof_encoding_contract, validate_linear_proof_profile_invariants,
    };
    use crate::ballot_privacy::linear_proof::profile_constants::{
        DEMO_GENERATED_PROFILE, ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT,
        ENCODED_SCORE_FIELD_GENERATED_PROFILE, RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT,
        RECEIVER_KEY_GENERATED_PROFILE,
    };
    use crate::encoding::CanonicalErrorCode;
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
        assert_eq!(
            parameter_contract.profile_id,
            "receiver-key-linear-module-lwe-v1"
        );
        assert_eq!(
            parameter_contract.coefficient_modulus,
            RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus
        );
        assert_eq!(
            parameter_contract.witness_l2_bound_squared,
            RECEIVER_KEY_GENERATED_PROFILE.exact_norm_bound_squared as u128
        );
        assert_eq!(
            parameter_contract.statement_rows,
            RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.statement_rows
        );
        assert_eq!(
            parameter_contract.statement_columns,
            RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.statement_columns
        );
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
        assert_eq!(
            parameter_contract.coefficient_modulus,
            ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus
        );
        assert_eq!(
            parameter_contract.witness_l2_bound_squared,
            ENCODED_SCORE_FIELD_GENERATED_PROFILE.exact_norm_bound_squared as u128
        );
        assert_eq!(
            parameter_contract.statement_rows,
            ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.statement_rows
        );
        assert_eq!(
            parameter_contract.statement_columns,
            ENCODED_SCORE_FIELD_GENERATED_PARAMETER_CONTRACT.statement_columns
        );
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
    fn unknown_proof_encoding_profile_uses_specific_error_code() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.profile_id = "unknown-linear-proof-encoding-v1".to_string();

        let error = linear_proof_profile_for_encoding(&proof_encoding)
            .expect_err("unknown proof profile should fail");

        assert_eq!(error.code, CanonicalErrorCode::UnknownProofProfile);
    }

    #[test]
    fn rejects_zero_response_vector_lengths() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.euclidean_response_vector_length = 0;

        let error = proof_encoding
            .validate()
            .expect_err("zero euclidean response vector length should fail");

        assert!(
            error
                .message
                .contains("proofEncoding.euclideanResponseVectorLength")
        );

        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.infinity_response_vector_length = 0;

        let error = proof_encoding
            .validate()
            .expect_err("zero infinity response vector length should fail");

        assert!(
            error
                .message
                .contains("proofEncoding.infinityResponseVectorLength")
        );
    }

    #[test]
    fn rejects_invalid_decompression_profile_invariants() {
        let mut proof_profile = profile_from_generated_constants(DEMO_GENERATED_PROFILE);
        proof_profile.decompression_gamma = 0;
        let error = validate_linear_proof_profile_invariants(proof_profile)
            .expect_err("zero decompression gamma should fail");
        assert!(error.message.contains("gamma"));

        let mut proof_profile = profile_from_generated_constants(DEMO_GENERATED_PROFILE);
        proof_profile.decompression_log2_modulus = 10;
        let error = validate_linear_proof_profile_invariants(proof_profile)
            .expect_err("understated decompression modulus bit length should fail");
        assert!(error.message.contains("rounded-up bit length"));

        let mut proof_profile = profile_from_generated_constants(DEMO_GENERATED_PROFILE);
        proof_profile.decompression_low_part_bound_squared = 0;
        let error = validate_linear_proof_profile_invariants(proof_profile)
            .expect_err("zero decompression low-part bound should fail");
        assert!(error.message.contains("low-part bound"));
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
