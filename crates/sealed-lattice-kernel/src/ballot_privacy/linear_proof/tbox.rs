use serde::{Deserialize, Serialize};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    norms::validate_norms, parameters::LinearProofEncoding, proof_coder::DecodedLinearProof,
    transcript::shake128_32,
};

pub const TBOX_Z34_TARGET_VECTOR_LENGTH: usize = 9;
pub const TBOX_GENERATOR_VECTOR_OFFSET: usize = 9;
pub const TBOX_GENERATOR_VECTOR_LENGTH: usize = 2;
pub const TBOX_HASH_MASK_ZERO_COEFFICIENTS: &[usize] = &[0, 32];

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct TboxPublicCheckSummary {
    pub z34_challenge_encoding_bytes: usize,
    pub z34_challenge_hash: String,
    pub generator_challenge_encoding_bytes: usize,
    pub generator_challenge_hash: String,
}

pub fn validate_tbox_public_checks(
    base_transcript_hash: &[u8; 32],
    decoded_proof: &DecodedLinearProof,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<TboxPublicCheckSummary> {
    proof_encoding.validate()?;
    validate_norms(decoded_proof, proof_encoding)?;
    validate_hash_mask_zero_positions(decoded_proof, proof_encoding)?;

    let target_commitment_vector = decoded_proof.commitment_target_vector();
    let expected_minimum_target_length = TBOX_GENERATOR_VECTOR_OFFSET
        .checked_add(TBOX_GENERATOR_VECTOR_LENGTH)
        .ok_or_else(|| invalid_tbox("tbox target vector length overflowed"))?;
    if target_commitment_vector.len() < expected_minimum_target_length {
        return Err(invalid_tbox(
            "tbox target commitment vector is too short for the demo layout",
        ));
    }

    let z34_challenge_encoding = encode_uniform_polynomial_vector(
        &target_commitment_vector[..TBOX_Z34_TARGET_VECTOR_LENGTH],
        proof_encoding,
    )?;
    let z34_challenge_hash = shake128_32(&[base_transcript_hash, &z34_challenge_encoding]);

    let generator_range_start = TBOX_GENERATOR_VECTOR_OFFSET;
    let generator_range_end = generator_range_start + TBOX_GENERATOR_VECTOR_LENGTH;
    let generator_challenge_encoding = encode_uniform_polynomial_vector(
        &target_commitment_vector[generator_range_start..generator_range_end],
        proof_encoding,
    )?;
    let generator_challenge_hash =
        shake128_32(&[&z34_challenge_hash, &generator_challenge_encoding]);

    Ok(TboxPublicCheckSummary {
        z34_challenge_encoding_bytes: z34_challenge_encoding.len(),
        z34_challenge_hash: to_hex(&z34_challenge_hash),
        generator_challenge_encoding_bytes: generator_challenge_encoding.len(),
        generator_challenge_hash: to_hex(&generator_challenge_hash),
    })
}

fn validate_hash_mask_zero_positions(
    decoded_proof: &DecodedLinearProof,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let hash_mask_vector = decoded_proof.hash_mask_vector();
    if hash_mask_vector.len() != proof_encoding.hash_mask_vector_length {
        return Err(invalid_tbox(
            "tbox hash-mask vector length does not match the proof encoding",
        ));
    }

    for polynomial in hash_mask_vector {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_tbox(
                "tbox hash-mask polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient_index in TBOX_HASH_MASK_ZERO_COEFFICIENTS {
            if *coefficient_index >= polynomial.len() {
                return Err(invalid_tbox(
                    "tbox hash-mask zero coefficient index is outside the ring degree",
                ));
            }
            if polynomial[*coefficient_index] != 0 {
                return Err(invalid_tbox(
                    "tbox hash-mask coefficient at a constrained zero position is nonzero",
                ));
            }
        }
    }

    Ok(())
}

fn encode_uniform_polynomial_vector(
    polynomials: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = TboxBitWriter::new();
    for polynomial in polynomials {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_tbox(
                "tbox polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            if *coefficient >= proof_encoding.coefficient_modulus {
                return Err(invalid_tbox("tbox polynomial coefficient is not canonical"));
            }
            writer.write_unsigned_little_endian_bits(
                *coefficient,
                proof_encoding.full_size_coefficient_bit_length,
            )?;
        }
    }

    writer.finish()
}

struct TboxBitWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl TboxBitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_tbox("tbox bit must be zero or one"));
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
            return Err(invalid_tbox(
                "tbox coder bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_tbox(
                "tbox coefficient does not fit in the requested bit length",
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

fn invalid_tbox(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::validate_tbox_public_checks;
    use crate::{
        ballot_privacy::linear_proof::{
            parameters::LinearProofEncoding, proof_coder::decode_linear_proof,
        },
        transcript_core::decode_hex,
    };

    fn decoded_valid_proof() -> (
        crate::ballot_privacy::linear_proof::proof_coder::DecodedLinearProof,
        LinearProofEncoding,
    ) {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        )))
        .expect("generated vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid generated vector should exist");
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
    fn valid_generated_proof_passes_tbox_public_checks() {
        let (decoded_proof, proof_encoding) = decoded_valid_proof();
        let base_transcript_hash = [0_u8; 32];

        let summary =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect("valid proof should pass public tbox checks");

        assert_eq!(summary.z34_challenge_encoding_bytes, 4_033);
        assert_eq!(summary.generator_challenge_encoding_bytes, 897);
        assert_eq!(summary.z34_challenge_hash.len(), 64);
        assert_eq!(summary.generator_challenge_hash.len(), 64);
    }

    #[test]
    fn hash_mask_generator_coefficients_must_be_zero() {
        let (mut decoded_proof, proof_encoding) = decoded_valid_proof();
        decoded_proof.hash_mask_vector_mut()[0][0] = 1;
        let base_transcript_hash = [0_u8; 32];

        let error =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect_err("nonzero constrained h coefficient should fail");

        assert!(error.message.contains("constrained zero position"));
    }

    #[test]
    fn tbox_hashes_bind_base_hash_and_public_target_slices() {
        let (decoded_proof, proof_encoding) = decoded_valid_proof();
        let zero_base_hash = [0_u8; 32];
        let mut different_base_hash = [0_u8; 32];
        different_base_hash[0] = 1;

        let zero_base_summary =
            validate_tbox_public_checks(&zero_base_hash, &decoded_proof, &proof_encoding)
                .expect("valid proof should pass public tbox checks");
        let different_base_summary =
            validate_tbox_public_checks(&different_base_hash, &decoded_proof, &proof_encoding)
                .expect("valid proof should pass public tbox checks");

        assert_ne!(
            zero_base_summary.z34_challenge_hash,
            different_base_summary.z34_challenge_hash
        );
        assert_ne!(
            zero_base_summary.generator_challenge_hash,
            different_base_summary.generator_challenge_hash
        );
    }

    #[test]
    fn z34_challenge_hash_binds_z34_target_slice() {
        let (mut decoded_proof, proof_encoding) = decoded_valid_proof();
        let base_transcript_hash = [0_u8; 32];
        let original_summary =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect("valid proof should pass public tbox checks");
        decoded_proof.commitment_target_vector_mut()[0][0] =
            (decoded_proof.commitment_target_vector()[0][0] + 1)
                % proof_encoding.coefficient_modulus;

        let mutated_summary =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect("mutated target slice should still be canonical but hash differently");

        assert_ne!(
            original_summary.z34_challenge_hash,
            mutated_summary.z34_challenge_hash
        );
    }

    #[test]
    fn generator_challenge_hash_binds_generator_target_slice_after_z34_hash() {
        let (mut decoded_proof, proof_encoding) = decoded_valid_proof();
        let base_transcript_hash = [0_u8; 32];
        let original_summary =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect("valid proof should pass public tbox checks");
        decoded_proof.commitment_target_vector_mut()[super::TBOX_GENERATOR_VECTOR_OFFSET][0] =
            (decoded_proof.commitment_target_vector()[super::TBOX_GENERATOR_VECTOR_OFFSET][0] + 1)
                % proof_encoding.coefficient_modulus;

        let mutated_summary =
            validate_tbox_public_checks(&base_transcript_hash, &decoded_proof, &proof_encoding)
                .expect("mutated generator slice should still be canonical but hash differently");

        assert_eq!(
            original_summary.z34_challenge_hash,
            mutated_summary.z34_challenge_hash
        );
        assert_ne!(
            original_summary.generator_challenge_hash,
            mutated_summary.generator_challenge_hash
        );
    }
}
