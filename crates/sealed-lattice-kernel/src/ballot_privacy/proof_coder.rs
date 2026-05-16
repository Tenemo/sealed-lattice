use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    transcript_core::decode_hex,
};

use super::linear_proof_parameters::LazerDemoProofEncoding;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct LinearProofBytes {
    bytes: Vec<u8>,
}

impl LinearProofBytes {
    pub fn from_hex(proof_hex: &str, expected_length: Option<usize>) -> CanonicalResult<Self> {
        let bytes = decode_hex(proof_hex)?;
        if bytes.is_empty() {
            return Err(invalid_proof("proof bytes must not be empty"));
        }
        if let Some(expected_length) = expected_length {
            match bytes.len().cmp(&expected_length) {
                std::cmp::Ordering::Less => {
                    return Err(invalid_proof("proof bytes are truncated"));
                }
                std::cmp::Ordering::Greater => {
                    return Err(invalid_proof("proof bytes contain trailing data"));
                }
                std::cmp::Ordering::Equal => {}
            }
        }

        Ok(Self { bytes })
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }

    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedProofFieldSpan {
    pub name: String,
    pub bit_offset: usize,
    pub bit_length: usize,
    pub byte_start: usize,
    pub byte_end_exclusive: usize,
}

#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct DecodedProofFieldLengths {
    pub full_proof_bytes: usize,
    pub fields: Vec<DecodedProofFieldSpan>,
    pub terminal_padding: DecodedProofFieldSpan,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedChallengePolynomial {
    encoded_coefficients: Vec<u64>,
    centered_coefficients: Vec<i64>,
}

impl DecodedChallengePolynomial {
    pub fn encoded_coefficients(&self) -> &[u64] {
        &self.encoded_coefficients
    }

    pub fn centered_coefficients(&self) -> &[i64] {
        &self.centered_coefficients
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedLazerDemoLinearProof {
    field_lengths: DecodedProofFieldLengths,
    commitment_target_vector: Vec<Vec<u64>>,
    hash_mask_vector: Vec<Vec<u64>>,
    compressed_commitment_vector: Vec<Vec<u64>>,
    challenge_polynomial: DecodedChallengePolynomial,
    hint_vector: Vec<Vec<i64>>,
    short_response_vector: Vec<Vec<i64>>,
    randomness_response_vector: Vec<Vec<i64>>,
    euclidean_response_vector: Vec<Vec<i64>>,
    infinity_response_vector: Vec<Vec<i64>>,
}

impl DecodedLazerDemoLinearProof {
    pub fn field_lengths(&self) -> &DecodedProofFieldLengths {
        &self.field_lengths
    }

    pub fn commitment_target_vector(&self) -> &[Vec<u64>] {
        &self.commitment_target_vector
    }

    pub fn hash_mask_vector(&self) -> &[Vec<u64>] {
        &self.hash_mask_vector
    }

    pub fn compressed_commitment_vector(&self) -> &[Vec<u64>] {
        &self.compressed_commitment_vector
    }

    pub fn challenge_polynomial(&self) -> &DecodedChallengePolynomial {
        &self.challenge_polynomial
    }

    pub fn hint_vector(&self) -> &[Vec<i64>] {
        &self.hint_vector
    }

    pub fn short_response_vector(&self) -> &[Vec<i64>] {
        &self.short_response_vector
    }

    pub fn randomness_response_vector(&self) -> &[Vec<i64>] {
        &self.randomness_response_vector
    }

    pub fn euclidean_response_vector(&self) -> &[Vec<i64>] {
        &self.euclidean_response_vector
    }

    pub fn infinity_response_vector(&self) -> &[Vec<i64>] {
        &self.infinity_response_vector
    }
}

pub fn decode_little_endian_fixed_width_coefficients(
    bytes: &[u8],
    coefficient_byte_length: usize,
    modulus: u64,
) -> CanonicalResult<Vec<u64>> {
    if coefficient_byte_length == 0 || coefficient_byte_length > 8 {
        return Err(invalid_proof(
            "coefficientByteLength must be between one and eight",
        ));
    }
    if !bytes.len().is_multiple_of(coefficient_byte_length) {
        return Err(invalid_proof(
            "coefficient byte stream length is not a multiple of coefficientByteLength",
        ));
    }

    let mut coefficients = Vec::with_capacity(bytes.len() / coefficient_byte_length);
    for chunk in bytes.chunks_exact(coefficient_byte_length) {
        let mut buffer = [0_u8; 8];
        buffer[..coefficient_byte_length].copy_from_slice(chunk);
        let coefficient = u64::from_le_bytes(buffer);
        if coefficient >= modulus {
            return Err(invalid_proof(
                "coefficient encoding is not canonical for the modulus",
            ));
        }
        coefficients.push(coefficient);
    }

    Ok(coefficients)
}

pub fn decode_lazer_demo_linear_proof_fields(
    proof_bytes: &[u8],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<DecodedProofFieldLengths> {
    Ok(decode_lazer_demo_linear_proof(proof_bytes, proof_encoding)?.field_lengths)
}

pub fn decode_lazer_demo_linear_proof(
    proof_bytes: &[u8],
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<DecodedLazerDemoLinearProof> {
    proof_encoding.validate()?;
    if proof_bytes.is_empty() {
        return Err(invalid_proof("proof bytes must not be empty"));
    }

    let mut reader = ProofBitReader::new(proof_bytes);
    let mut fields = Vec::with_capacity(9);
    let (commitment_target_vector_span, commitment_target_vector) =
        record_decoded_value(&mut reader, "commitmentTargetVector", |reader| {
            decode_uniform_polynomial_vector(
                reader,
                proof_encoding.target_commitment_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.coefficient_modulus,
                proof_encoding.full_size_coefficient_bit_length,
            )
        })?;
    fields.push(commitment_target_vector_span);
    let (hash_mask_vector_span, hash_mask_vector) =
        record_decoded_value(&mut reader, "hashMaskVector", |reader| {
            decode_uniform_polynomial_vector(
                reader,
                proof_encoding.hash_mask_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.coefficient_modulus,
                proof_encoding.full_size_coefficient_bit_length,
            )
        })?;
    fields.push(hash_mask_vector_span);
    let (compressed_commitment_vector_span, compressed_commitment_vector) =
        record_decoded_value(&mut reader, "compressedCommitmentVector", |reader| {
            decode_uniform_polynomial_vector(
                reader,
                proof_encoding.compressed_commitment_vector_length,
                proof_encoding.ring_degree,
                bit_capacity(proof_encoding.compressed_coefficient_bit_length)?,
                proof_encoding.compressed_coefficient_bit_length,
            )
        })?;
    fields.push(compressed_commitment_vector_span);
    let (challenge_polynomial_span, challenge_polynomial) =
        record_decoded_value(&mut reader, "challengePolynomial", |reader| {
            decode_challenge_polynomial(
                reader,
                proof_encoding.ring_degree,
                proof_encoding.challenge_coefficient_modulus,
                proof_encoding.challenge_coefficient_bit_length,
            )
        })?;
    fields.push(challenge_polynomial_span);
    let (hint_vector_span, hint_vector) =
        record_decoded_value(&mut reader, "hintVector", |reader| {
            decode_hint_polynomial_vector(
                reader,
                proof_encoding.hint_vector_length,
                proof_encoding.ring_degree,
            )
        })?;
    fields.push(hint_vector_span);
    let (short_response_vector_span, short_response_vector) =
        record_decoded_value(&mut reader, "shortResponseVector", |reader| {
            decode_gaussian_polynomial_vector(
                reader,
                proof_encoding.short_response_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.short_response_log2_standard_deviation,
            )
        })?;
    fields.push(short_response_vector_span);
    let (randomness_response_vector_span, randomness_response_vector) =
        record_decoded_value(&mut reader, "randomnessResponseVector", |reader| {
            decode_gaussian_polynomial_vector(
                reader,
                proof_encoding.randomness_response_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.randomness_response_log2_standard_deviation,
            )
        })?;
    fields.push(randomness_response_vector_span);
    let (euclidean_response_vector_span, euclidean_response_vector) =
        record_decoded_value(&mut reader, "euclideanResponseVector", |reader| {
            decode_gaussian_polynomial_vector(
                reader,
                proof_encoding.euclidean_response_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.euclidean_response_log2_standard_deviation,
            )
        })?;
    fields.push(euclidean_response_vector_span);
    let (infinity_response_vector_span, infinity_response_vector) =
        record_decoded_value(&mut reader, "infinityResponseVector", |reader| {
            decode_gaussian_polynomial_vector(
                reader,
                proof_encoding.infinity_response_vector_length,
                proof_encoding.ring_degree,
                proof_encoding.infinity_response_log2_standard_deviation,
            )
        })?;
    fields.push(infinity_response_vector_span);

    let padding_start_bit = reader.bit_offset();
    reader.finish()?;

    let field_lengths = DecodedProofFieldLengths {
        full_proof_bytes: proof_bytes.len(),
        fields,
        terminal_padding: DecodedProofFieldSpan {
            name: "terminalPadding".to_string(),
            bit_offset: padding_start_bit,
            bit_length: reader.bit_offset() - padding_start_bit,
            byte_start: padding_start_bit / 8,
            byte_end_exclusive: proof_bytes.len(),
        },
    };

    Ok(DecodedLazerDemoLinearProof {
        field_lengths,
        commitment_target_vector,
        hash_mask_vector,
        compressed_commitment_vector,
        challenge_polynomial,
        hint_vector,
        short_response_vector,
        randomness_response_vector,
        euclidean_response_vector,
        infinity_response_vector,
    })
}

struct ProofBitReader<'proof> {
    proof_bytes: &'proof [u8],
    bit_offset: usize,
}

impl<'proof> ProofBitReader<'proof> {
    fn new(proof_bytes: &'proof [u8]) -> Self {
        Self {
            proof_bytes,
            bit_offset: 0,
        }
    }

    fn bit_offset(&self) -> usize {
        self.bit_offset
    }

    fn read_bit(&mut self) -> CanonicalResult<u8> {
        if self.bit_offset >= self.proof_bytes.len() * 8 {
            return Err(invalid_proof(
                "proof encoding ended before the current field was complete",
            ));
        }

        let byte_value = self.proof_bytes[self.bit_offset / 8];
        let bit_index = self.bit_offset % 8;
        self.bit_offset += 1;

        Ok((byte_value >> bit_index) & 1)
    }

    fn read_unsigned_little_endian_bits(&mut self, bit_count: usize) -> CanonicalResult<u64> {
        if bit_count > 63 {
            return Err(invalid_proof(
                "proof coder bit fields must fit in a positive signed word",
            ));
        }

        let mut value = 0_u64;
        for bit_index in 0..bit_count {
            value |= u64::from(self.read_bit()?) << bit_index;
        }

        Ok(value)
    }

    fn finish(&mut self) -> CanonicalResult<()> {
        if self.bit_offset >= self.proof_bytes.len() * 8 {
            return Err(invalid_proof("proof encoding has no terminal padding bit"));
        }

        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        let high_mask = u8::MAX << bit_index;
        let expected = 1_u8 << bit_index;
        if self.proof_bytes[byte_index] & high_mask != expected {
            return Err(invalid_proof(
                "proof encoding has noncanonical terminal padding",
            ));
        }

        self.bit_offset = (byte_index + 1) * 8;
        if self.bit_offset != self.proof_bytes.len() * 8 {
            return Err(invalid_proof("proof encoding contains trailing data"));
        }

        Ok(())
    }
}

fn record_decoded_value<DecodedValue>(
    reader: &mut ProofBitReader,
    name: &'static str,
    decode: impl FnOnce(&mut ProofBitReader) -> CanonicalResult<DecodedValue>,
) -> CanonicalResult<(DecodedProofFieldSpan, DecodedValue)> {
    let start_bit = reader.bit_offset();
    let decoded_value = decode(reader)?;
    let end_bit = reader.bit_offset();

    Ok((
        DecodedProofFieldSpan {
            name: name.to_string(),
            bit_offset: start_bit,
            bit_length: end_bit - start_bit,
            byte_start: start_bit / 8,
            byte_end_exclusive: end_bit.div_ceil(8),
        },
        decoded_value,
    ))
}

fn decode_uniform_polynomial_vector(
    reader: &mut ProofBitReader,
    vector_length: usize,
    ring_degree: usize,
    modulus: u64,
    coefficient_bit_length: usize,
) -> CanonicalResult<Vec<Vec<u64>>> {
    let coefficient_count = vector_length
        .checked_mul(ring_degree)
        .ok_or_else(|| invalid_proof("proof vector coefficient count overflowed"))?;
    let mut decoded_coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let encoded_coefficient =
            reader.read_unsigned_little_endian_bits(coefficient_bit_length)?;
        if encoded_coefficient >= modulus {
            return Err(invalid_proof(
                "uniform polynomial coefficient is not canonical",
            ));
        }
        decoded_coefficients.push(encoded_coefficient);
    }

    Ok(decoded_coefficients
        .chunks_exact(ring_degree)
        .map(<[u64]>::to_vec)
        .collect())
}

fn decode_challenge_polynomial(
    reader: &mut ProofBitReader,
    ring_degree: usize,
    coefficient_modulus: u64,
    coefficient_bit_length: usize,
) -> CanonicalResult<DecodedChallengePolynomial> {
    let encoded_polynomial = decode_uniform_polynomial_vector(
        reader,
        1,
        ring_degree,
        coefficient_modulus,
        coefficient_bit_length,
    )?
    .into_iter()
    .next()
    .ok_or_else(|| invalid_proof("challenge polynomial must contain one polynomial"))?;
    let half_modulus = coefficient_modulus / 2;
    let centered_coefficients = encoded_polynomial
        .iter()
        .map(|coefficient| {
            if *coefficient > half_modulus {
                i64::try_from(*coefficient)
                    .and_then(|coefficient_value| {
                        i64::try_from(coefficient_modulus)
                            .map(|modulus_value| coefficient_value - modulus_value)
                    })
                    .map_err(|_| invalid_proof("challenge coefficient does not fit in i64"))
            } else {
                i64::try_from(*coefficient)
                    .map_err(|_| invalid_proof("challenge coefficient does not fit in i64"))
            }
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    Ok(DecodedChallengePolynomial {
        encoded_coefficients: encoded_polynomial,
        centered_coefficients,
    })
}

fn decode_hint_polynomial_vector(
    reader: &mut ProofBitReader,
    vector_length: usize,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let coefficient_count = vector_length
        .checked_mul(ring_degree)
        .ok_or_else(|| invalid_proof("proof hint coefficient count overflowed"))?;
    let mut decoded_coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let first_bit = reader.read_bit()?;
        let second_bit = reader.read_bit()?;
        let decoded_coefficient = match (first_bit, second_bit) {
            (0, 0) => 0,
            (0, 1) => 1,
            (1, 0) => -1,
            (1, 1) => {
                let mut zero_run_length = 0_i64;
                while reader.read_bit()? == 0 {
                    zero_run_length = zero_run_length.checked_add(1).ok_or_else(|| {
                        invalid_proof("hint coefficient unary run length overflowed")
                    })?;
                }
                if zero_run_length % 2 == 0 {
                    (zero_run_length + 4) / 2
                } else {
                    -((zero_run_length + 3) / 2)
                }
            }
            _ => unreachable!("bits are normalized to zero or one"),
        };
        decoded_coefficients.push(decoded_coefficient);
    }

    Ok(decoded_coefficients
        .chunks_exact(ring_degree)
        .map(<[i64]>::to_vec)
        .collect())
}

fn decode_gaussian_polynomial_vector(
    reader: &mut ProofBitReader,
    vector_length: usize,
    ring_degree: usize,
    log2_standard_deviation: usize,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let binary_tail_bit_length = log2_standard_deviation
        .checked_add(1)
        .ok_or_else(|| invalid_proof("gaussian coder tail bit length overflowed"))?;
    let coefficient_count = vector_length
        .checked_mul(ring_degree)
        .ok_or_else(|| invalid_proof("proof gaussian coefficient count overflowed"))?;
    let mut decoded_coefficients = Vec::with_capacity(coefficient_count);
    for _ in 0..coefficient_count {
        let mut one_run_length = 0_i64;
        while reader.read_bit()? == 1 {
            one_run_length = one_run_length
                .checked_add(1)
                .ok_or_else(|| invalid_proof("gaussian coefficient unary run length overflowed"))?;
        }
        let low_bits = reader.read_unsigned_little_endian_bits(binary_tail_bit_length)?;
        let centered_low_bits = sign_extend_unsigned_value(low_bits, binary_tail_bit_length)?;
        let high_part = if one_run_length % 2 == 0 {
            -(one_run_length / 2)
        } else {
            (one_run_length + 1) / 2
        };
        let scale = 1_i64
            .checked_shl(
                u32::try_from(binary_tail_bit_length)
                    .map_err(|_| invalid_proof("gaussian scale bit length does not fit in u32"))?,
            )
            .ok_or_else(|| invalid_proof("gaussian scale overflowed"))?;
        let decoded_coefficient = scale
            .checked_mul(high_part)
            .and_then(|scaled_high_part| scaled_high_part.checked_add(centered_low_bits))
            .ok_or_else(|| invalid_proof("gaussian coefficient overflowed"))?;
        decoded_coefficients.push(decoded_coefficient);
    }

    Ok(decoded_coefficients
        .chunks_exact(ring_degree)
        .map(<[i64]>::to_vec)
        .collect())
}

fn sign_extend_unsigned_value(unsigned_value: u64, bit_length: usize) -> CanonicalResult<i64> {
    if bit_length == 0 || bit_length >= 63 {
        return Err(invalid_proof(
            "signed proof coder bit length must be between one and sixty-two",
        ));
    }
    let unsigned_value = i64::try_from(unsigned_value)
        .map_err(|_| invalid_proof("signed proof coder value does not fit in i64"))?;
    let sign_threshold = 1_i64
        .checked_shl(
            u32::try_from(bit_length - 1)
                .map_err(|_| invalid_proof("signed proof coder bit length does not fit in u32"))?,
        )
        .ok_or_else(|| invalid_proof("signed proof coder sign threshold overflowed"))?;
    let signed_modulus = 1_i64
        .checked_shl(
            u32::try_from(bit_length)
                .map_err(|_| invalid_proof("signed proof coder bit length does not fit in u32"))?,
        )
        .ok_or_else(|| invalid_proof("signed proof coder modulus overflowed"))?;

    if unsigned_value >= sign_threshold {
        unsigned_value
            .checked_sub(signed_modulus)
            .ok_or_else(|| invalid_proof("signed proof coder subtraction overflowed"))
    } else {
        Ok(unsigned_value)
    }
}

fn bit_capacity(bit_length: usize) -> CanonicalResult<u64> {
    if bit_length == 0 || bit_length > 63 {
        return Err(invalid_proof(
            "proof coder bit capacity must be between one and sixty-three",
        ));
    }

    Ok(1_u64 << bit_length)
}

fn invalid_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LinearProofBytes, decode_lazer_demo_linear_proof, decode_lazer_demo_linear_proof_fields,
        decode_little_endian_fixed_width_coefficients,
    };
    use crate::{
        ballot_privacy::linear_proof_parameters::{
            LazerDemoProofEncoding, demo_linear_proof_encoding_contract,
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
    fn rejects_truncated_and_extended_proof_bytes() {
        assert!(
            LinearProofBytes::from_hex("00ff", Some(3))
                .expect_err("short proof should fail")
                .message
                .contains("truncated")
        );
        assert!(
            LinearProofBytes::from_hex("00ff", Some(1))
                .expect_err("extended proof should fail")
                .message
                .contains("trailing")
        );
    }

    #[test]
    fn rejects_noncanonical_fixed_width_coefficients() {
        let error = decode_little_endian_fixed_width_coefficients(&[17, 0], 1, 17)
            .expect_err("coefficient equal to modulus should fail");

        assert!(error.message.contains("not canonical"));
    }

    #[test]
    fn rejects_structured_proof_with_missing_padding() {
        let proof_encoding = demo_linear_proof_encoding_contract();
        let proof = vec![0_u8; proof_encoding.full_size_coefficient_bit_length];

        let error = decode_lazer_demo_linear_proof_fields(&proof, &proof_encoding)
            .expect_err("short structured proof should fail before padding");

        assert!(
            error.message.contains("ended before")
                || error.message.contains("terminal padding")
                || error.message.contains("not canonical")
        );
    }

    #[test]
    fn decodes_generated_upstream_proof_objects() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let proof_encoding: LazerDemoProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");

        let decoded_proof = decode_lazer_demo_linear_proof(&proof_bytes, &proof_encoding)
            .expect("valid generated proof bytes should decode");

        assert_eq!(decoded_proof.commitment_target_vector().len(), 12);
        assert_eq!(decoded_proof.hash_mask_vector().len(), 2);
        assert_eq!(decoded_proof.compressed_commitment_vector().len(), 13);
        assert_eq!(
            decoded_proof
                .challenge_polynomial()
                .encoded_coefficients()
                .len(),
            64
        );
        assert_eq!(decoded_proof.hint_vector().len(), 13);
        assert_eq!(decoded_proof.short_response_vector().len(), 33);
        assert_eq!(decoded_proof.randomness_response_vector().len(), 47);
        assert_eq!(decoded_proof.euclidean_response_vector().len(), 4);
        assert_eq!(decoded_proof.infinity_response_vector().len(), 4);
        assert!(
            decoded_proof
                .challenge_polynomial()
                .centered_coefficients()
                .iter()
                .all(|coefficient| (-8..=8).contains(coefficient))
        );
        assert!(
            decoded_proof
                .short_response_vector()
                .iter()
                .flatten()
                .any(|coefficient| *coefficient != 0)
        );
        assert_eq!(decoded_proof.field_lengths().fields.len(), 9);
        assert!(decoded_proof.field_lengths().terminal_padding.bit_length > 0);
    }

    #[test]
    fn structured_decoder_rejects_generated_truncated_and_extended_proofs() {
        for (case_name, expected_message) in [
            (
                "truncated-proof",
                "proof encoding ended before the current field was complete",
            ),
            ("extended-proof", "proof encoding contains trailing data"),
        ] {
            let vector_case = generated_vector_case(case_name);
            let proof_encoding: LazerDemoProofEncoding =
                serde_json::from_value(vector_case["proofEncoding"].clone())
                    .expect("proof encoding should deserialize");
            let proof_hex = vector_case["proofHex"]
                .as_str()
                .expect("proof hex should be present");
            let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");

            let error = decode_lazer_demo_linear_proof(&proof_bytes, &proof_encoding)
                .expect_err("malformed generated proof should fail structured decoding");

            assert!(error.message.contains(expected_message));
        }
    }
}
