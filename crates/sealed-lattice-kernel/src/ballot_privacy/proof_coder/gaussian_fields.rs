use super::*;

const MAXIMUM_GAUSSIAN_UNARY_RUN_LENGTH: i64 = 1_048_576;
pub(super) fn decode_gaussian_polynomial_vector(
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
            if one_run_length > MAXIMUM_GAUSSIAN_UNARY_RUN_LENGTH {
                return Err(invalid_proof(
                    "gaussian coefficient unary run length exceeds the decoder cap",
                ));
            }
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

pub(super) fn encode_gaussian_polynomial_vector(
    writer: &mut ProofBitWriter,
    polynomials: &[Vec<i64>],
    expected_vector_length: usize,
    ring_degree: usize,
    log2_standard_deviation: usize,
) -> CanonicalResult<()> {
    if polynomials.len() != expected_vector_length {
        return Err(invalid_proof(
            "gaussian polynomial vector length does not match the proof encoding",
        ));
    }
    let binary_tail_bit_length = log2_standard_deviation
        .checked_add(1)
        .ok_or_else(|| invalid_proof("gaussian coder tail bit length overflowed"))?;
    let scale = 1_i64
        .checked_shl(
            u32::try_from(binary_tail_bit_length)
                .map_err(|_| invalid_proof("gaussian scale bit length does not fit in u32"))?,
        )
        .ok_or_else(|| invalid_proof("gaussian scale overflowed"))?;
    let centered_low_minimum = -(scale / 2);
    let centered_low_maximum = scale / 2 - 1;

    for polynomial in polynomials {
        if polynomial.len() != ring_degree {
            return Err(invalid_proof(
                "gaussian polynomial degree does not match the proof encoding",
            ));
        }
        for coefficient in polynomial {
            let centered_low_bits = coefficient.rem_euclid(scale);
            let centered_low_bits = if centered_low_bits > centered_low_maximum {
                centered_low_bits - scale
            } else {
                centered_low_bits
            };
            if centered_low_bits < centered_low_minimum || centered_low_bits > centered_low_maximum
            {
                return Err(invalid_proof(
                    "gaussian low bits are outside centered range",
                ));
            }
            let high_part = coefficient
                .checked_sub(centered_low_bits)
                .ok_or_else(|| invalid_proof("gaussian high-part subtraction overflowed"))?
                / scale;
            let one_run_length = if high_part <= 0 {
                high_part
                    .checked_mul(-2)
                    .ok_or_else(|| invalid_proof("gaussian run length overflowed"))?
            } else {
                high_part
                    .checked_mul(2)
                    .and_then(|doubled| doubled.checked_sub(1))
                    .ok_or_else(|| invalid_proof("gaussian run length overflowed"))?
            };
            let one_run_length = usize::try_from(one_run_length)
                .map_err(|_| invalid_proof("gaussian run length is negative"))?;
            if one_run_length
                > usize::try_from(MAXIMUM_GAUSSIAN_UNARY_RUN_LENGTH)
                    .expect("gaussian run cap fits usize")
            {
                return Err(invalid_proof(
                    "gaussian coefficient unary run length exceeds the encoder cap",
                ));
            }
            for _ in 0..one_run_length {
                writer.write_bit(1)?;
            }
            writer.write_bit(0)?;

            let encoded_low_bits = if centered_low_bits < 0 {
                u64::try_from(
                    centered_low_bits
                        .checked_add(scale)
                        .ok_or_else(|| invalid_proof("gaussian low-bit wrap overflowed"))?,
                )
            } else {
                u64::try_from(centered_low_bits)
            }
            .map_err(|_| invalid_proof("gaussian low bits do not fit in u64"))?;
            writer.write_unsigned_little_endian_bits(encoded_low_bits, binary_tail_bit_length)?;
        }
    }

    Ok(())
}

pub(super) fn sign_extend_unsigned_value(
    unsigned_value: u64,
    bit_length: usize,
) -> CanonicalResult<i64> {
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

pub(super) fn bit_capacity(bit_length: usize) -> CanonicalResult<u64> {
    if bit_length == 0 || bit_length > 63 {
        return Err(invalid_proof(
            "proof coder bit capacity must be between one and sixty-three",
        ));
    }

    Ok(1_u64 << bit_length)
}

pub(super) fn invalid_proof(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LinearProofBytes, decode_linear_proof, decode_linear_proof_fields,
        decode_little_endian_fixed_width_coefficients, encode_linear_proof,
    };
    use crate::{
        ballot_privacy::linear_proof_parameters::{
            LinearProofEncoding, demo_linear_proof_encoding_contract,
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

        let error = decode_linear_proof_fields(&proof, &proof_encoding)
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
        let proof_encoding: LinearProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");

        let decoded_proof = decode_linear_proof(&proof_bytes, &proof_encoding)
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
    fn reencodes_generated_upstream_proof_byte_identically() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let proof_encoding: LinearProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");
        let decoded_proof = decode_linear_proof(&proof_bytes, &proof_encoding)
            .expect("valid generated proof bytes should decode");

        let encoded_proof = encode_linear_proof(&decoded_proof, &proof_encoding)
            .expect("decoded proof should re-encode");

        assert_eq!(encoded_proof, proof_bytes);
    }

    #[test]
    fn reencoding_changes_when_decoded_proof_object_changes() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let proof_encoding: LinearProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_hex = vector_case["proofHex"]
            .as_str()
            .expect("proof hex should be present");
        let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");
        let mut decoded_proof = decode_linear_proof(&proof_bytes, &proof_encoding)
            .expect("valid generated proof bytes should decode");
        decoded_proof.commitment_target_vector[0][0] += 1;

        let encoded_proof = encode_linear_proof(&decoded_proof, &proof_encoding)
            .expect("mutated decoded proof should re-encode");

        assert_ne!(encoded_proof, proof_bytes);
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
            let proof_encoding: LinearProofEncoding =
                serde_json::from_value(vector_case["proofEncoding"].clone())
                    .expect("proof encoding should deserialize");
            let proof_hex = vector_case["proofHex"]
                .as_str()
                .expect("proof hex should be present");
            let proof_bytes = decode_hex(proof_hex).expect("proof bytes should decode");

            let error = decode_linear_proof(&proof_bytes, &proof_encoding)
                .expect_err("malformed generated proof should fail structured decoding");

            assert!(error.message.contains(expected_message));
        }
    }
}
