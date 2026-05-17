use serde::{Deserialize, Serialize};

use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    lazer_demo_public_parameters::derive_lazer_abdlop_public_parameters,
    linear_proof_parameters::{LazerDemoProofEncoding, linear_proof_profile_for_encoding},
    linear_proof_transcript::shake128_32,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::DecodedLazerDemoLinearProof,
};

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LazerDemoAbdlopLinearOpeningSummary {
    pub recovered_high_bits_vector_length: usize,
    pub recovered_high_bits_encoding_bytes: usize,
    pub recovered_high_bits_hash: String,
    pub low_part_l2_squared: u128,
    pub low_part_bound_squared: u128,
}

pub fn validate_lazer_demo_abdlop_linear_opening(
    base_transcript_hash: &[u8; 32],
    public_randomness: &[u8; 32],
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LazerDemoProofEncoding,
) -> CanonicalResult<LazerDemoAbdlopLinearOpeningSummary> {
    proof_encoding.validate()?;
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;

    let public_parameters =
        derive_lazer_abdlop_public_parameters(public_randomness, proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
    )?;
    let short_response_vector =
        signed_polynomial_vector_to_canonical(proof_ring, decoded_proof.short_response_vector())?;
    let randomness_response_vector = signed_polynomial_vector_to_canonical(
        proof_ring,
        decoded_proof.randomness_response_vector(),
    )?;
    let challenge_polynomial =
        shifted_challenge_polynomial(decoded_proof, proof_ring, proof_profile)?;
    let compressed_commitment_vector = PolynomialVector::new(
        proof_ring,
        decoded_proof.compressed_commitment_vector().to_vec(),
    )?;

    let commitment_product = public_parameters
        .commitment_key_matrix
        .multiply_vector(&short_response_vector)?;
    let opening_product = public_parameters
        .opening_key_matrix
        .multiply_vector(&randomness_response_vector)?;
    let product_sum = commitment_product.add(&opening_product)?;
    let challenge_commitment_product = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        &compressed_commitment_vector,
    )?;
    let recovery_input = product_sum.sub(&challenge_commitment_product)?;
    let recovered_high_bits = recover_decompressed_high_bits(
        recovery_input.entries(),
        decoded_proof.hint_vector(),
        proof_encoding,
        proof_profile,
    )?;
    let low_part_l2_squared = compute_low_part_l2_squared(
        proof_ring,
        recovery_input.entries(),
        &recovered_high_bits,
        proof_profile,
    )?;
    if low_part_l2_squared > proof_profile.decompression_low_part_bound_squared {
        return Err(invalid_abdlop(
            "ABDLOP decompression low part exceeds the proof profile l2 bound",
        ));
    }
    let recovered_high_bits_encoding =
        encode_lazer_demo_recovered_high_bits(&recovered_high_bits, proof_encoding, proof_profile)?;
    let recovered_high_bits_hash =
        shake128_32(&[base_transcript_hash, &recovered_high_bits_encoding]);

    Ok(LazerDemoAbdlopLinearOpeningSummary {
        recovered_high_bits_vector_length: recovered_high_bits.len(),
        recovered_high_bits_encoding_bytes: recovered_high_bits_encoding.len(),
        recovered_high_bits_hash: to_hex(&recovered_high_bits_hash),
        low_part_l2_squared,
        low_part_bound_squared: proof_profile.decompression_low_part_bound_squared,
    })
}

fn signed_polynomial_vector_to_canonical(
    ring: PolynomialRing,
    polynomials: &[Vec<i64>],
) -> CanonicalResult<PolynomialVector> {
    let canonical_polynomials = polynomials
        .iter()
        .map(|polynomial| {
            if polynomial.len() != ring.degree() {
                return Err(invalid_abdlop(
                    "signed polynomial degree does not match the proof ring",
                ));
            }
            polynomial
                .iter()
                .map(|coefficient| positive_mod_i128(i128::from(*coefficient), ring.modulus()))
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(ring, canonical_polynomials)
}

fn shifted_challenge_polynomial(
    decoded_proof: &DecodedLazerDemoLinearProof,
    ring: PolynomialRing,
    proof_profile: super::linear_proof_parameters::LazerLinearProofProfile,
) -> CanonicalResult<Vec<u64>> {
    if decoded_proof
        .challenge_polynomial()
        .centered_coefficients()
        .len()
        != ring.degree()
    {
        return Err(invalid_abdlop(
            "challenge polynomial degree does not match the proof ring",
        ));
    }
    let shift_multiplier = 1_i128
        .checked_shl(
            u32::try_from(proof_profile.decompression_shift)
                .map_err(|_| invalid_abdlop("decompression shift does not fit in u32"))?,
        )
        .ok_or_else(|| invalid_abdlop("decompression shift overflowed"))?;

    decoded_proof
        .challenge_polynomial()
        .centered_coefficients()
        .iter()
        .map(|coefficient| {
            positive_mod_i128(
                i128::from(*coefficient)
                    .checked_mul(shift_multiplier)
                    .ok_or_else(|| invalid_abdlop("shifted challenge coefficient overflowed"))?,
                ring.modulus(),
            )
        })
        .collect()
}

fn multiply_polynomial_by_vector(
    ring: PolynomialRing,
    polynomial: &[u64],
    vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    if vector.ring() != ring {
        return Err(invalid_abdlop(
            "polynomial/vector multiplication rings do not match",
        ));
    }
    let entries = vector
        .entries()
        .iter()
        .map(|entry| ring.mul_negacyclic(polynomial, entry))
        .collect::<CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(ring, entries)
}

fn recover_decompressed_high_bits(
    recovery_input: &[Vec<u64>],
    hint_vector: &[Vec<i64>],
    proof_encoding: &LazerDemoProofEncoding,
    proof_profile: super::linear_proof_parameters::LazerLinearProofProfile,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if recovery_input.len() != hint_vector.len() {
        return Err(invalid_abdlop(
            "ABDLOP recovery input and hint vector lengths do not match",
        ));
    }

    recovery_input
        .iter()
        .zip(hint_vector)
        .map(|(input_polynomial, hint_polynomial)| {
            if input_polynomial.len() != hint_polynomial.len() {
                return Err(invalid_abdlop(
                    "ABDLOP recovery polynomial and hint polynomial degrees do not match",
                ));
            }
            input_polynomial
                .iter()
                .zip(hint_polynomial)
                .map(|(coefficient, hint)| {
                    let high_bits =
                        decompression_high_bits(*coefficient, proof_encoding, proof_profile)?;
                    positive_mod_with_i128_modulus(
                        high_bits
                            .checked_add(i128::from(*hint))
                            .ok_or_else(|| invalid_abdlop("ABDLOP hint addition overflowed"))?,
                        proof_profile.decompression_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

fn decompression_high_bits(
    coefficient: u64,
    proof_encoding: &LazerDemoProofEncoding,
    proof_profile: super::linear_proof_parameters::LazerLinearProofProfile,
) -> CanonicalResult<i128> {
    if coefficient >= proof_encoding.coefficient_modulus {
        return Err(invalid_abdlop(
            "ABDLOP recovery coefficient is not canonical",
        ));
    }
    let mut low_part = i128::from(coefficient)
        .checked_rem(proof_profile.decompression_gamma)
        .ok_or_else(|| invalid_abdlop("ABDLOP low-part reduction failed"))?;
    let half_gamma = proof_profile.decompression_gamma / 2;
    if low_part > half_gamma {
        low_part -= proof_profile.decompression_gamma;
    }

    let high_numerator = i128::from(coefficient)
        .checked_sub(low_part)
        .ok_or_else(|| invalid_abdlop("ABDLOP high-part subtraction overflowed"))?;
    if high_numerator == i128::from(proof_encoding.coefficient_modulus - 1) {
        Ok(0)
    } else {
        Ok(high_numerator / proof_profile.decompression_gamma)
    }
}

fn compute_low_part_l2_squared(
    ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    recovered_high_bits: &[Vec<u64>],
    proof_profile: super::linear_proof_parameters::LazerLinearProofProfile,
) -> CanonicalResult<u128> {
    if recovery_input.len() != recovered_high_bits.len() {
        return Err(invalid_abdlop("ABDLOP low-part input lengths do not match"));
    }
    let mut squared_sum = 0_u128;
    for (input_polynomial, high_bits_polynomial) in recovery_input.iter().zip(recovered_high_bits) {
        if input_polynomial.len() != ring.degree() || high_bits_polynomial.len() != ring.degree() {
            return Err(invalid_abdlop(
                "ABDLOP low-part polynomial degree does not match the proof ring",
            ));
        }
        for (input_coefficient, high_bits_coefficient) in
            input_polynomial.iter().zip(high_bits_polynomial)
        {
            let low_part = positive_mod_i128(
                i128::from(*input_coefficient)
                    .checked_sub(
                        proof_profile
                            .decompression_gamma
                            .checked_mul(i128::from(*high_bits_coefficient))
                            .ok_or_else(|| {
                                invalid_abdlop("ABDLOP low-part multiplication overflowed")
                            })?,
                    )
                    .ok_or_else(|| invalid_abdlop("ABDLOP low-part subtraction overflowed"))?,
                ring.modulus(),
            )?;
            let centered_abs = u128::from(ring.centered_abs(low_part)?);
            squared_sum = squared_sum
                .checked_add(centered_abs.checked_mul(centered_abs).ok_or_else(|| {
                    invalid_abdlop("ABDLOP low-part coefficient square overflowed")
                })?)
                .ok_or_else(|| invalid_abdlop("ABDLOP low-part l2 norm overflowed"))?;
        }
    }

    Ok(squared_sum)
}

fn encode_lazer_demo_recovered_high_bits(
    polynomials: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
    proof_profile: super::linear_proof_parameters::LazerLinearProofProfile,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = RecoveredHighBitsWriter::new();
    for polynomial in polynomials {
        if polynomial.len() != proof_encoding.ring_degree {
            return Err(invalid_abdlop(
                "ABDLOP recovered high-bits polynomial degree does not match the proof ring",
            ));
        }
        for coefficient in polynomial {
            if *coefficient
                >= u64::try_from(proof_profile.decompression_modulus).map_err(|_| {
                    invalid_abdlop("ABDLOP decompression modulus does not fit in u64")
                })?
            {
                return Err(invalid_abdlop(
                    "ABDLOP recovered high-bits coefficient is not canonical",
                ));
            }
            writer.write_unsigned_little_endian_bits(
                *coefficient,
                proof_profile.decompression_log2_modulus,
            )?;
        }
    }

    writer.finish()
}

struct RecoveredHighBitsWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl RecoveredHighBitsWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_abdlop("ABDLOP encoding bit must be zero or one"));
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
            return Err(invalid_abdlop(
                "ABDLOP encoding bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_abdlop(
                "ABDLOP encoding value does not fit in the requested bit length",
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

fn positive_mod_i128(value: i128, modulus: u64) -> CanonicalResult<u64> {
    positive_mod_with_i128_modulus(value, i128::from(modulus))
}

fn positive_mod_with_i128_modulus(value: i128, modulus: i128) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_abdlop("positive modulus must be greater than one"));
    }
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    u64::try_from(reduced)
        .map_err(|_| invalid_abdlop("positive modular reduction does not fit in u64"))
}

fn invalid_abdlop(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::validate_lazer_demo_abdlop_linear_opening;
    use crate::{
        ballot_privacy::{
            abdlop_commitment::hash_lazer_demo_abdlop_commitment,
            linear_proof_parameters::{LazerDemoProofEncoding, LinearProofParameterSet},
            linear_proof_statement::{
                LinearProofTargetCoefficientRepresentation,
                derive_lazer_demo_linear_statement_transcript,
            },
            proof_coder::decode_lazer_demo_linear_proof,
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
    fn valid_generated_proof_recovers_abdlop_linear_opening() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let parameter_set: LinearProofParameterSet =
            serde_json::from_value(vector_case["parameterSet"].clone())
                .expect("parameter set should deserialize");
        let proof_encoding: LazerDemoProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let statement_matrix_coefficients: Vec<Vec<Vec<u64>>> =
            serde_json::from_value(vector_case["statementMatrixCoefficients"].clone())
                .expect("statement matrix should deserialize");
        let target_vector_coefficients: Vec<Vec<u64>> =
            serde_json::from_value(vector_case["targetVectorCoefficients"].clone())
                .expect("target vector should deserialize");
        let public_randomness_bytes = decode_hex(
            vector_case["publicRandomnessHex"]
                .as_str()
                .expect("public randomness should be present"),
        )
        .expect("public randomness should decode");
        let mut public_randomness = [0_u8; 32];
        public_randomness.copy_from_slice(&public_randomness_bytes);
        let proof_bytes = decode_hex(
            vector_case["proofHex"]
                .as_str()
                .expect("proof hex should be present"),
        )
        .expect("proof bytes should decode");
        let decoded_proof = decode_lazer_demo_linear_proof(&proof_bytes, &proof_encoding)
            .expect("proof should decode");
        let statement_transcript = derive_lazer_demo_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("statement transcript should derive");
        let abdlop_commitment_hash = hash_lazer_demo_abdlop_commitment(
            &statement_transcript.public_parameters_and_statement_hash,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("ABDLOP commitment hash should derive");

        let summary = validate_lazer_demo_abdlop_linear_opening(
            &abdlop_commitment_hash,
            &public_randomness,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("valid generated proof should recover ABDLOP linear opening");

        assert_eq!(summary.recovered_high_bits_vector_length, 13);
        assert_eq!(summary.recovered_high_bits_encoding_bytes, 3_849);
        assert!(summary.low_part_l2_squared <= summary.low_part_bound_squared);
        assert_eq!(summary.recovered_high_bits_hash.len(), 64);
    }

    #[test]
    fn abdlop_linear_opening_binds_public_randomness() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
        let proof_encoding: LazerDemoProofEncoding =
            serde_json::from_value(vector_case["proofEncoding"].clone())
                .expect("proof encoding should deserialize");
        let proof_bytes = decode_hex(
            vector_case["proofHex"]
                .as_str()
                .expect("proof hex should be present"),
        )
        .expect("proof bytes should decode");
        let decoded_proof = decode_lazer_demo_linear_proof(&proof_bytes, &proof_encoding)
            .expect("proof should decode");
        let zero_public_randomness = [0_u8; 32];
        let mut changed_public_randomness = [0_u8; 32];
        changed_public_randomness[0] = 1;
        let base_hash = [0_u8; 32];

        let zero_summary = validate_lazer_demo_abdlop_linear_opening(
            &base_hash,
            &zero_public_randomness,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("zero-randomness opening should recover");
        let changed_summary = validate_lazer_demo_abdlop_linear_opening(
            &base_hash,
            &changed_public_randomness,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("changed-randomness opening should still be well-shaped");

        assert_ne!(
            zero_summary.recovered_high_bits_hash,
            changed_summary.recovered_high_bits_hash
        );
    }
}
