use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::{
    linear_proof_parameters::LazerDemoProofEncoding, linear_proof_transcript::shake128_32,
    proof_coder::DecodedLazerDemoLinearProof,
};

pub const LAZER_DEMO_ABDLOP_COMMITMENT_HASH_BYTES: usize = 32;

pub fn encode_lazer_demo_abdlop_commitment(
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    encode_lazer_demo_compressed_commitment_vector(
        decoded_proof.compressed_commitment_vector(),
        proof_encoding,
    )
}

pub(crate) fn encode_lazer_demo_compressed_commitment_vector(
    compressed_commitment_vector: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    proof_encoding.validate()?;
    if compressed_commitment_vector.len() != proof_encoding.compressed_commitment_vector_length {
        return Err(invalid_commitment(
            "compressed ABDLOP commitment length does not match the proof encoding",
        ));
    }

    let mut writer = CommitmentBitWriter::new();
    let coefficient_modulus = 1_u64
        .checked_shl(
            u32::try_from(proof_encoding.compressed_coefficient_bit_length).map_err(|_| {
                invalid_commitment("compressed coefficient bit length does not fit in u32")
            })?,
        )
        .ok_or_else(|| invalid_commitment("compressed coefficient modulus overflowed"))?;
    for polynomial in compressed_commitment_vector {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_commitment(
                "compressed ABDLOP commitment polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            if *coefficient >= coefficient_modulus {
                return Err(invalid_commitment(
                    "compressed ABDLOP commitment coefficient is not canonical",
                ));
            }
            writer.write_unsigned_little_endian_bits(
                *coefficient,
                proof_encoding.compressed_coefficient_bit_length,
            )?;
        }
    }

    writer.finish()
}

pub fn hash_lazer_demo_abdlop_commitment(
    base_hash: &[u8; LAZER_DEMO_ABDLOP_COMMITMENT_HASH_BYTES],
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<[u8; LAZER_DEMO_ABDLOP_COMMITMENT_HASH_BYTES]> {
    let encoded_commitment = encode_lazer_demo_abdlop_commitment(decoded_proof, proof_encoding)?;

    Ok(shake128_32(&[base_hash, &encoded_commitment]))
}

struct CommitmentBitWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl CommitmentBitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_commitment("commitment bit must be zero or one"));
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
            return Err(invalid_commitment(
                "commitment coder bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_commitment(
                "commitment coefficient does not fit in the requested bit length",
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

fn invalid_commitment(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{encode_lazer_demo_abdlop_commitment, hash_lazer_demo_abdlop_commitment};
    use crate::{
        ballot_privacy::{
            linear_proof_parameters::LazerDemoProofEncoding,
            proof_coder::decode_lazer_demo_linear_proof,
        },
        hashing::to_hex,
        transcript_core::decode_hex,
    };

    fn decoded_valid_proof() -> (
        crate::ballot_privacy::proof_coder::DecodedLazerDemoLinearProof,
        LazerDemoProofEncoding,
    ) {
        let vectors: serde_json::Value = serde_json::from_str(include_str!(
            "../../../../test-vectors/ballot-privacy/proof-backend-linear-vectors.json"
        ))
        .expect("generated vector file should parse");
        let vector_case = vectors["cases"]
            .as_array()
            .expect("generated vector file should contain cases")
            .iter()
            .find(|vector_case| vector_case["caseName"] == "valid-small-linear-proof")
            .expect("valid generated vector should exist");
        let proof_encoding: LazerDemoProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");
        let decoded_proof = decode_lazer_demo_linear_proof(&proof_bytes, &proof_encoding)
            .expect("valid proof should decode");

        (decoded_proof, proof_encoding)
    }

    #[test]
    fn encodes_demo_abdlop_commitment_with_terminal_padding() {
        let (decoded_proof, proof_encoding) = decoded_valid_proof();

        let encoded_commitment =
            encode_lazer_demo_abdlop_commitment(&decoded_proof, &proof_encoding)
                .expect("commitment should encode");

        assert_eq!(encoded_commitment.len(), 4_785);
        assert_eq!(encoded_commitment.last(), Some(&1));
    }

    #[test]
    fn hashes_demo_abdlop_commitment_with_base_hash_binding() {
        let (decoded_proof, proof_encoding) = decoded_valid_proof();
        let zero_base_hash = [0_u8; 32];
        let mut different_base_hash = [0_u8; 32];
        different_base_hash[0] = 1;

        let left_hash =
            hash_lazer_demo_abdlop_commitment(&zero_base_hash, &decoded_proof, &proof_encoding)
                .expect("commitment hash should compute");
        let right_hash = hash_lazer_demo_abdlop_commitment(
            &different_base_hash,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("commitment hash should compute");

        assert_ne!(left_hash, right_hash);
        assert_eq!(to_hex(&left_hash).len(), 64);
    }
}
