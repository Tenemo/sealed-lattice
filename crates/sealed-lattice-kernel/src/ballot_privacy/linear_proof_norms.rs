use serde::{Deserialize, Serialize};

use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{
    linear_proof_parameters::{LinearProofEncoding, linear_proof_profile_for_encoding},
    linear_proof_profile_constants::DEMO_GENERATED_PROFILE,
    proof_coder::DecodedLazerDemoLinearProof,
};

pub const LINEAR_PROOF_CHALLENGE_CENTERED_BOUND: i64 =
    DEMO_GENERATED_PROFILE.challenge_centered_bound;
pub const LINEAR_PROOF_EUCLIDEAN_RESPONSE_BOUND_SQUARED: u128 =
    DEMO_GENERATED_PROFILE.euclidean_response_bound_squared;
pub const LINEAR_PROOF_INFINITY_RESPONSE_BOUND: u128 =
    DEMO_GENERATED_PROFILE.infinity_response_bound;

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinearProofNormSummary {
    pub challenge_centered_linf: u64,
    pub short_response_l2_squared: u128,
    pub short_response_bound_squared: u128,
    pub euclidean_response_l2_squared: u128,
    pub euclidean_response_bound_squared: u128,
    pub infinity_response_linf: u128,
    pub infinity_response_bound: u128,
}

pub fn validate_linear_proof_norms(
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<LinearProofNormSummary> {
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    let challenge_centered_linf =
        centered_linf(decoded_proof.challenge_polynomial().centered_coefficients())?;
    if challenge_centered_linf > proof_profile.challenge_centered_bound.unsigned_abs() {
        return Err(invalid_norm(
            "challenge coefficient exceeds the proof profile bound",
        ));
    }

    let short_response_l2_squared = l2_squared(decoded_proof.short_response_vector())?;
    let short_response_bound_squared = short_response_bound_squared(proof_encoding, proof_profile)?;
    if short_response_l2_squared > short_response_bound_squared {
        return Err(invalid_norm(
            "short response exceeds the proof profile l2 bound",
        ));
    }

    let euclidean_response_l2_squared = l2_squared(decoded_proof.euclidean_response_vector())?;
    if euclidean_response_l2_squared > proof_profile.euclidean_response_bound_squared {
        return Err(invalid_norm(
            "euclidean response exceeds the proof profile l2 bound",
        ));
    }

    let infinity_response_linf = linf(decoded_proof.infinity_response_vector())?;
    if infinity_response_linf > proof_profile.infinity_response_bound {
        return Err(invalid_norm(
            "infinity response exceeds the proof profile infinity bound",
        ));
    }

    Ok(LinearProofNormSummary {
        challenge_centered_linf,
        short_response_l2_squared,
        short_response_bound_squared,
        euclidean_response_l2_squared,
        euclidean_response_bound_squared: proof_profile.euclidean_response_bound_squared,
        infinity_response_linf,
        infinity_response_bound: proof_profile.infinity_response_bound,
    })
}

fn short_response_bound_squared(
    proof_encoding: &LinearProofEncoding,
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<u128> {
    let ring_degree = proof_encoding.ring_degree as u128;
    let standard_deviation_scale = 1_u128
        .checked_shl(
            u32::try_from(
                proof_encoding
                    .short_response_log2_standard_deviation
                    .checked_mul(2)
                    .ok_or_else(|| invalid_norm("short response scale overflowed"))?,
            )
            .map_err(|_| invalid_norm("short response scale shift does not fit in u32"))?,
        )
        .ok_or_else(|| invalid_norm("short response scale shift overflowed"))?;

    proof_profile
        .short_response_message_length
        .checked_mul(2)
        .and_then(|value| value.checked_mul(ring_degree))
        .and_then(|value| value.checked_mul(proof_profile.short_response_bound_scale_numerator))
        .and_then(|value| value.checked_mul(standard_deviation_scale))
        .map(|value| value / proof_profile.short_response_bound_scale_denominator)
        .ok_or_else(|| invalid_norm("short response bound overflowed"))
}

fn l2_squared(polynomials: &[Vec<i64>]) -> CanonicalResult<u128> {
    let mut sum = 0_u128;
    for coefficient in polynomials.iter().flatten() {
        let absolute_value = coefficient.unsigned_abs() as u128;
        let squared = absolute_value
            .checked_mul(absolute_value)
            .ok_or_else(|| invalid_norm("coefficient square overflowed"))?;
        sum = sum
            .checked_add(squared)
            .ok_or_else(|| invalid_norm("l2 norm overflowed"))?;
    }

    Ok(sum)
}

fn linf(polynomials: &[Vec<i64>]) -> CanonicalResult<u128> {
    polynomials
        .iter()
        .flatten()
        .map(|coefficient| coefficient.unsigned_abs() as u128)
        .max()
        .ok_or_else(|| invalid_norm("norm input must not be empty"))
}

fn centered_linf(coefficients: &[i64]) -> CanonicalResult<u64> {
    coefficients
        .iter()
        .map(|coefficient| coefficient.unsigned_abs())
        .max()
        .ok_or_else(|| invalid_norm("challenge polynomial must not be empty"))
}

fn invalid_norm(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LINEAR_PROOF_EUCLIDEAN_RESPONSE_BOUND_SQUARED, LINEAR_PROOF_INFINITY_RESPONSE_BOUND,
        validate_linear_proof_norms,
    };
    use crate::{
        ballot_privacy::{
            linear_proof_parameters::LinearProofEncoding, proof_coder::decode_linear_proof,
        },
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

    fn decoded_valid_proof() -> (
        crate::ballot_privacy::proof_coder::DecodedLazerDemoLinearProof,
        LinearProofEncoding,
    ) {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let proof_encoding: LinearProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");
        let decoded_proof =
            decode_linear_proof(&proof_bytes, &proof_encoding).expect("valid proof should decode");

        (decoded_proof, proof_encoding)
    }

    #[test]
    fn generated_valid_proof_passes_demo_norm_checks() {
        let (decoded_proof, proof_encoding) = decoded_valid_proof();

        let summary = validate_linear_proof_norms(&decoded_proof, &proof_encoding)
            .expect("valid proof should pass norm checks");

        assert!(summary.short_response_l2_squared <= summary.short_response_bound_squared);
        assert!(
            summary.euclidean_response_l2_squared <= LINEAR_PROOF_EUCLIDEAN_RESPONSE_BOUND_SQUARED
        );
        assert!(summary.infinity_response_linf <= LINEAR_PROOF_INFINITY_RESPONSE_BOUND);
    }

    #[test]
    fn euclidean_response_bound_failure_is_reported() {
        let (mut decoded_proof, proof_encoding) = decoded_valid_proof();
        decoded_proof.euclidean_response_vector_mut()[0][0] =
            (LINEAR_PROOF_EUCLIDEAN_RESPONSE_BOUND_SQUARED as f64).sqrt() as i64 + 10_000;

        let error = validate_linear_proof_norms(&decoded_proof, &proof_encoding)
            .expect_err("oversized euclidean response should fail");

        assert!(error.message.contains("euclidean response"));
    }

    #[test]
    fn infinity_response_bound_failure_is_reported() {
        let (mut decoded_proof, proof_encoding) = decoded_valid_proof();
        decoded_proof.infinity_response_vector_mut()[0][0] =
            i64::try_from(LINEAR_PROOF_INFINITY_RESPONSE_BOUND + 1)
                .expect("bound should fit in i64");

        let error = validate_linear_proof_norms(&decoded_proof, &proof_encoding)
            .expect_err("oversized infinity response should fail");

        assert!(error.message.contains("infinity response"));
    }
}
