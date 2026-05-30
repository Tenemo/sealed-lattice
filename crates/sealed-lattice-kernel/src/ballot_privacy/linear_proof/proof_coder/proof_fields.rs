use super::*;
use crate::{encoding::CanonicalResult, transcript_core::decode_hex};

use super::parameters::LinearProofEncoding;

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
pub struct DecodedLinearProof {
    field_lengths: DecodedProofFieldLengths,
    pub(super) commitment_target_vector: Vec<Vec<u64>>,
    hash_mask_vector: Vec<Vec<u64>>,
    compressed_commitment_vector: Vec<Vec<u64>>,
    challenge_polynomial: DecodedChallengePolynomial,
    hint_vector: Vec<Vec<i64>>,
    short_response_vector: Vec<Vec<i64>>,
    randomness_response_vector: Vec<Vec<i64>>,
    euclidean_response_vector: Vec<Vec<i64>>,
    infinity_response_vector: Vec<Vec<i64>>,
}

impl DecodedLinearProof {
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

    #[cfg(test)]
    pub(crate) fn commitment_target_vector_mut(&mut self) -> &mut [Vec<u64>] {
        &mut self.commitment_target_vector
    }

    #[cfg(test)]
    pub(crate) fn hash_mask_vector_mut(&mut self) -> &mut [Vec<u64>] {
        &mut self.hash_mask_vector
    }

    #[cfg(test)]
    pub(crate) fn euclidean_response_vector_mut(&mut self) -> &mut [Vec<i64>] {
        &mut self.euclidean_response_vector
    }

    #[cfg(test)]
    pub(crate) fn infinity_response_vector_mut(&mut self) -> &mut [Vec<i64>] {
        &mut self.infinity_response_vector
    }
}

#[cfg(test)]
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

#[cfg(test)]
pub fn decode_linear_proof_fields(
    proof_bytes: &[u8],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<DecodedProofFieldLengths> {
    Ok(decode_linear_proof(proof_bytes, proof_encoding)?.field_lengths)
}

pub fn decode_linear_proof(
    proof_bytes: &[u8],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<DecodedLinearProof> {
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

    Ok(DecodedLinearProof {
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

pub fn encode_linear_proof(
    decoded_proof: &DecodedLinearProof,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    proof_encoding.validate()?;

    let mut writer = ProofBitWriter::new();
    encode_uniform_polynomial_vector(
        &mut writer,
        decoded_proof.commitment_target_vector(),
        proof_encoding.target_commitment_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    encode_uniform_polynomial_vector(
        &mut writer,
        decoded_proof.hash_mask_vector(),
        proof_encoding.hash_mask_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    encode_uniform_polynomial_vector(
        &mut writer,
        decoded_proof.compressed_commitment_vector(),
        proof_encoding.compressed_commitment_vector_length,
        proof_encoding.ring_degree,
        bit_capacity(proof_encoding.compressed_coefficient_bit_length)?,
        proof_encoding.compressed_coefficient_bit_length,
    )?;
    encode_uniform_polynomial_vector(
        &mut writer,
        &[decoded_proof
            .challenge_polynomial()
            .encoded_coefficients()
            .to_vec()],
        1,
        proof_encoding.ring_degree,
        proof_encoding.challenge_coefficient_modulus,
        proof_encoding.challenge_coefficient_bit_length,
    )?;
    encode_hint_polynomial_vector(
        &mut writer,
        decoded_proof.hint_vector(),
        proof_encoding.hint_vector_length,
        proof_encoding.ring_degree,
    )?;
    encode_gaussian_polynomial_vector(
        &mut writer,
        decoded_proof.short_response_vector(),
        proof_encoding.short_response_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.short_response_log2_standard_deviation,
    )?;
    encode_gaussian_polynomial_vector(
        &mut writer,
        decoded_proof.randomness_response_vector(),
        proof_encoding.randomness_response_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.randomness_response_log2_standard_deviation,
    )?;
    encode_gaussian_polynomial_vector(
        &mut writer,
        decoded_proof.euclidean_response_vector(),
        proof_encoding.euclidean_response_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.euclidean_response_log2_standard_deviation,
    )?;
    encode_gaussian_polynomial_vector(
        &mut writer,
        decoded_proof.infinity_response_vector(),
        proof_encoding.infinity_response_vector_length,
        proof_encoding.ring_degree,
        proof_encoding.infinity_response_log2_standard_deviation,
    )?;

    writer.finish()
}

pub(crate) struct LinearProofComponents {
    pub(crate) commitment_target_vector: Vec<Vec<u64>>,
    pub(crate) hash_mask_vector: Vec<Vec<u64>>,
    pub(crate) compressed_commitment_vector: Vec<Vec<u64>>,
    pub(crate) centered_challenge_polynomial: Vec<i64>,
    pub(crate) hint_vector: Vec<Vec<i64>>,
    pub(crate) short_response_vector: Vec<Vec<i64>>,
    pub(crate) randomness_response_vector: Vec<Vec<i64>>,
    pub(crate) euclidean_response_vector: Vec<Vec<i64>>,
    pub(crate) infinity_response_vector: Vec<Vec<i64>>,
}

pub(crate) fn encode_linear_proof_components(
    components: LinearProofComponents,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    proof_encoding.validate()?;
    if components.centered_challenge_polynomial.len() != proof_encoding.ring_degree {
        return Err(invalid_proof(
            "challenge polynomial degree does not match the proof encoding",
        ));
    }
    let challenge_bound =
        i64::try_from(proof_encoding.challenge_coefficient_modulus / 2).map_err(|_| {
            invalid_proof("challenge coefficient modulus does not fit in a signed integer")
        })?;
    let encoded_challenge_polynomial = components
        .centered_challenge_polynomial
        .iter()
        .map(|coefficient| {
            if !(-challenge_bound..=challenge_bound).contains(coefficient) {
                return Err(invalid_proof(
                    "challenge coefficient is outside the centered encoding range",
                ));
            }
            if *coefficient < 0 {
                u64::try_from(
                    i128::from(proof_encoding.challenge_coefficient_modulus)
                        + i128::from(*coefficient),
                )
                .map_err(|_| invalid_proof("negative challenge coefficient cannot encode"))
            } else {
                u64::try_from(*coefficient)
                    .map_err(|_| invalid_proof("challenge coefficient cannot encode"))
            }
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    let decoded_proof = DecodedLinearProof {
        field_lengths: DecodedProofFieldLengths {
            full_proof_bytes: 0,
            fields: Vec::new(),
            terminal_padding: DecodedProofFieldSpan {
                name: "terminalPadding".to_string(),
                bit_offset: 0,
                bit_length: 0,
                byte_start: 0,
                byte_end_exclusive: 0,
            },
        },
        commitment_target_vector: components.commitment_target_vector,
        hash_mask_vector: components.hash_mask_vector,
        compressed_commitment_vector: components.compressed_commitment_vector,
        challenge_polynomial: DecodedChallengePolynomial {
            encoded_coefficients: encoded_challenge_polynomial,
            centered_coefficients: components.centered_challenge_polynomial,
        },
        hint_vector: components.hint_vector,
        short_response_vector: components.short_response_vector,
        randomness_response_vector: components.randomness_response_vector,
        euclidean_response_vector: components.euclidean_response_vector,
        infinity_response_vector: components.infinity_response_vector,
    };

    encode_linear_proof(&decoded_proof, proof_encoding)
}

pub(super) struct ProofBitReader<'proof> {
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

    pub(super) fn read_bit(&mut self) -> CanonicalResult<u8> {
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

    pub(super) fn read_unsigned_little_endian_bits(
        &mut self,
        bit_count: usize,
    ) -> CanonicalResult<u64> {
        if bit_count == 0 || bit_count > 63 {
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
        // Strict canonical terminator (anti-malleability): the next bit must be
        // 1, every higher bit in that byte must be 0, and no trailing bytes may
        // follow. Any deviation is a noncanonical (malleable) encoding.
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

pub(super) struct ProofBitWriter {
    proof_bytes: Vec<u8>,
    bit_offset: usize,
}

impl ProofBitWriter {
    fn new() -> Self {
        Self {
            proof_bytes: Vec::new(),
            bit_offset: 0,
        }
    }

    pub(super) fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_proof("proof bit must be zero or one"));
        }
        let byte_index = self.bit_offset / 8;
        let bit_index = self.bit_offset % 8;
        if byte_index == self.proof_bytes.len() {
            self.proof_bytes.push(0);
        }
        if bit == 1 {
            self.proof_bytes[byte_index] |= 1_u8 << bit_index;
        }
        self.bit_offset += 1;

        Ok(())
    }

    pub(super) fn write_unsigned_little_endian_bits(
        &mut self,
        value: u64,
        bit_count: usize,
    ) -> CanonicalResult<()> {
        if bit_count == 0 || bit_count > 63 {
            return Err(invalid_proof(
                "proof coder bit fields must fit in a positive signed word",
            ));
        }
        if bit_count < 64 && value >= (1_u64 << bit_count) {
            return Err(invalid_proof(
                "proof coder value does not fit in the requested bit length",
            ));
        }
        for bit_index in 0..bit_count {
            self.write_bit(((value >> bit_index) & 1) as u8)?;
        }

        Ok(())
    }

    fn finish(mut self) -> CanonicalResult<Vec<u8>> {
        // Encoder counterpart to ProofBitReader::finish: terminal 1-bit then
        // zero-pad to the byte boundary.
        self.write_bit(1)?;
        while !self.bit_offset.is_multiple_of(8) {
            self.write_bit(0)?;
        }

        Ok(self.proof_bytes)
    }
}

pub(super) fn record_decoded_value<DecodedValue>(
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

pub(super) fn decode_uniform_polynomial_vector(
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

pub(super) fn encode_uniform_polynomial_vector(
    writer: &mut ProofBitWriter,
    polynomials: &[Vec<u64>],
    expected_vector_length: usize,
    ring_degree: usize,
    modulus: u64,
    coefficient_bit_length: usize,
) -> CanonicalResult<()> {
    if polynomials.len() != expected_vector_length {
        return Err(invalid_proof(
            "uniform polynomial vector length does not match the proof encoding",
        ));
    }
    for polynomial in polynomials {
        if polynomial.len() != ring_degree {
            return Err(invalid_proof(
                "uniform polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            if *coefficient >= modulus {
                return Err(invalid_proof(
                    "uniform polynomial coefficient is not canonical",
                ));
            }
            writer.write_unsigned_little_endian_bits(*coefficient, coefficient_bit_length)?;
        }
    }

    Ok(())
}

pub(super) fn decode_challenge_polynomial(
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
    // Center each challenge coefficient to a balanced residue: values above
    // half the modulus map to the negative representative c - modulus.
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

pub(super) fn decode_hint_polynomial_vector(
    reader: &mut ProofBitReader,
    vector_length: usize,
    ring_degree: usize,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let coefficient_count = vector_length
        .checked_mul(ring_degree)
        .ok_or_else(|| invalid_proof("proof hint coefficient count overflowed"))?;
    // LaZer hint codeword table (must stay bit-identical to the LaZer format):
    //   00 -> 0, 01 -> +1, 10 -> -1, and 11 -> a unary zero-run terminated by a
    //   1 bit encoding |v| >= 2: even run -> (run+4)/2, odd run -> -((run+3)/2).
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

pub(super) fn encode_hint_polynomial_vector(
    writer: &mut ProofBitWriter,
    polynomials: &[Vec<i64>],
    expected_vector_length: usize,
    ring_degree: usize,
) -> CanonicalResult<()> {
    if polynomials.len() != expected_vector_length {
        return Err(invalid_proof(
            "hint polynomial vector length does not match the proof encoding",
        ));
    }
    for polynomial in polynomials {
        if polynomial.len() != ring_degree {
            return Err(invalid_proof(
                "hint polynomial degree does not match the proof encoding",
            ));
        }
        // Inverse of the decoder codeword table; encoder/decoder must stay
        // bit-identical. |v| >= 2 emits 11, a zero-run, then a terminating 1:
        // positive run = 2v - 4 (even), negative run = -2v - 3 (odd).
        for coefficient in polynomial {
            match *coefficient {
                0 => {
                    writer.write_bit(0)?;
                    writer.write_bit(0)?;
                }
                1 => {
                    writer.write_bit(0)?;
                    writer.write_bit(1)?;
                }
                -1 => {
                    writer.write_bit(1)?;
                    writer.write_bit(0)?;
                }
                coefficient if coefficient >= 2 => {
                    writer.write_bit(1)?;
                    writer.write_bit(1)?;
                    let zero_run_length = usize::try_from(
                        coefficient
                            .checked_mul(2)
                            .and_then(|doubled| doubled.checked_sub(4))
                            .ok_or_else(|| invalid_proof("hint coefficient overflowed"))?,
                    )
                    .map_err(|_| invalid_proof("hint coefficient run length is negative"))?;
                    for _ in 0..zero_run_length {
                        writer.write_bit(0)?;
                    }
                    writer.write_bit(1)?;
                }
                coefficient => {
                    writer.write_bit(1)?;
                    writer.write_bit(1)?;
                    let zero_run_length = usize::try_from(
                        coefficient
                            .checked_mul(-2)
                            .and_then(|negated_double| negated_double.checked_sub(3))
                            .ok_or_else(|| invalid_proof("hint coefficient overflowed"))?,
                    )
                    .map_err(|_| invalid_proof("hint coefficient run length is negative"))?;
                    for _ in 0..zero_run_length {
                        writer.write_bit(0)?;
                    }
                    writer.write_bit(1)?;
                }
            }
        }
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{ProofBitReader, ProofBitWriter};

    #[test]
    fn bit_fields_reject_zero_width() {
        let mut writer = ProofBitWriter::new();
        assert!(writer.write_unsigned_little_endian_bits(0, 0).is_err());

        let bytes = [0_u8];
        let mut reader = ProofBitReader::new(&bytes);
        assert!(reader.read_unsigned_little_endian_bits(0).is_err());
    }
}
