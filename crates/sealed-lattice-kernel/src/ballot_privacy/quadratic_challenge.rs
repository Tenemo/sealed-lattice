use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    linear_proof_parameters::{LinearProofEncoding, linear_proof_profile_for_encoding},
    linear_proof_public_parameters::{
        LINEAR_PROOF_PROOF_RING_DEGREE, derive_abdlop_public_parameters,
    },
    linear_proof_rng::sample_linear_proof_autostable_challenge_coefficients,
    linear_proof_transcript::shake128_32,
    many_quadratic::ManyQuadraticFold,
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::DecodedLazerDemoLinearProof,
    sparse_polynomial_vector::SparsePolynomialVector,
};

const QUADRATIC_TARGET_VECTOR_LENGTH: usize = 12;
const QUADRATIC_MESSAGE_LENGTH: usize = 11;

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LazerDemoQuadraticChallengeSummary {
    pub(crate) recomputed_challenge_hash: String,
    pub(crate) short_response_l2_squared: u128,
    pub(crate) short_response_l2_bound_squared: u128,
    pub(crate) low_part_l2_squared: u128,
    pub(crate) low_part_l2_bound_squared: u128,
    pub(crate) hint_infinity_norm: u128,
}

pub(crate) fn validate_quadratic_challenge(
    challenge_seed: &[u8; 32],
    public_randomness: &[u8; 32],
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LinearProofEncoding,
    many_quadratic_fold: &ManyQuadraticFold,
) -> CanonicalResult<LazerDemoQuadraticChallengeSummary> {
    proof_encoding.validate()?;
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    validate_quadratic_equation_shapes(decoded_proof, proof_encoding, many_quadratic_fold)?;

    let proof_ring = PolynomialRing::new(
        proof_encoding.ring_degree,
        proof_encoding.coefficient_modulus,
    )?;
    let public_parameters = derive_abdlop_public_parameters(public_randomness, proof_encoding)?;
    let challenge_polynomial = challenge_polynomial_to_canonical_proof_ring(
        proof_ring,
        decoded_proof.challenge_polynomial().centered_coefficients(),
    )?;
    let shifted_challenge_polynomial = multiply_polynomial_by_power_of_two(
        proof_ring,
        &challenge_polynomial,
        proof_profile.decompression_shift,
    )?;
    let short_response_vector =
        signed_polynomial_vector_to_canonical(proof_ring, decoded_proof.short_response_vector())?;
    let randomness_response_vector = signed_polynomial_vector_to_canonical(
        proof_ring,
        decoded_proof.randomness_response_vector(),
    )?;
    let compressed_commitment_vector = PolynomialVector::new(
        proof_ring,
        decoded_proof.compressed_commitment_vector().to_vec(),
    )?;
    let target_commitment_vector = PolynomialVector::new(
        proof_ring,
        decoded_proof.commitment_target_vector().to_vec(),
    )?;

    let recovery_input = recover_quadratic_equation_decompression_input(
        proof_ring,
        &public_parameters.commitment_key_matrix,
        &public_parameters.opening_key_matrix,
        &short_response_vector,
        &randomness_response_vector,
        &shifted_challenge_polynomial,
        &compressed_commitment_vector,
    )?;
    let recovered_high_bits = recover_quadratic_equation_high_bits(
        recovery_input.entries(),
        decoded_proof.hint_vector(),
        proof_encoding,
        proof_profile,
    )?;
    let low_part_l2_squared = compute_quadratic_equation_low_part_l2_squared(
        proof_ring,
        recovery_input.entries(),
        &recovered_high_bits,
        proof_profile,
    )?;
    if low_part_l2_squared > proof_profile.decompression_low_part_bound_squared {
        return Err(invalid_quadratic_challenge(
            "quadratic decompression low part exceeds the proof profile l2 bound",
        ));
    }

    let reconstructed_message_vector = recover_quadratic_equation_message_vector(
        proof_ring,
        &public_parameters.message_key_matrix,
        &challenge_polynomial,
        &randomness_response_vector,
        &target_commitment_vector,
    )?;
    let verifier_polynomial = recover_quadratic_equation_verifier_polynomial(
        LazerDemoQuadraticVerifierPolynomialInput {
            proof_ring,
            challenge_polynomial: &challenge_polynomial,
            folded_equation: &many_quadratic_fold.folded_equation,
            short_response_vector: &short_response_vector,
            reconstructed_message_vector: &reconstructed_message_vector,
            message_key_matrix: &public_parameters.message_key_matrix,
            randomness_response_vector: &randomness_response_vector,
            target_commitment_vector: &target_commitment_vector,
        },
    )?;
    let challenge_encoding = encode_quadratic_challenge_input(
        proof_ring,
        &target_commitment_vector.entries()[QUADRATIC_MESSAGE_LENGTH..],
        &verifier_polynomial,
        &recovered_high_bits,
        proof_encoding,
        proof_profile,
    )?;
    let recomputed_challenge_seed = shake128_32(&[challenge_seed, &challenge_encoding]);
    let recomputed_challenge_coefficients = sample_linear_proof_autostable_challenge_coefficients(
        proof_ring.degree(),
        proof_profile.challenge_centered_bound,
        proof_profile.challenge_coefficient_bit_length,
        &recomputed_challenge_seed,
        0,
    )?;
    if recomputed_challenge_coefficients
        != decoded_proof.challenge_polynomial().centered_coefficients()
    {
        return Err(invalid_quadratic_challenge(
            "quadratic verifier challenge recomputation did not match the proof challenge",
        ));
    }

    let short_response_l2_squared =
        signed_polynomial_l2_squared(decoded_proof.short_response_vector())?;
    let short_response_l2_bound_squared =
        short_response_l2_bound_squared(proof_encoding, proof_profile)?;
    if short_response_l2_squared > short_response_l2_bound_squared {
        return Err(invalid_quadratic_challenge(
            "quadratic short response exceeds the demo l2 bound",
        ));
    }

    let hint_infinity_norm = signed_polynomial_infinity_norm(decoded_proof.hint_vector())?;
    if hint_infinity_norm
        .checked_mul(2)
        .ok_or_else(|| invalid_quadratic_challenge("hint infinity norm overflowed"))?
        > u128::try_from(proof_profile.decompression_modulus).map_err(|_| {
            invalid_quadratic_challenge("decompression modulus does not fit in u128")
        })?
    {
        return Err(invalid_quadratic_challenge(
            "quadratic hint infinity norm exceeds the demo bound",
        ));
    }

    Ok(LazerDemoQuadraticChallengeSummary {
        recomputed_challenge_hash: to_hex(&recomputed_challenge_seed),
        short_response_l2_squared,
        short_response_l2_bound_squared,
        low_part_l2_squared,
        low_part_l2_bound_squared: proof_profile.decompression_low_part_bound_squared,
        hint_infinity_norm,
    })
}

fn validate_quadratic_equation_shapes(
    decoded_proof: &DecodedLazerDemoLinearProof,
    proof_encoding: &LinearProofEncoding,
    many_quadratic_fold: &ManyQuadraticFold,
) -> CanonicalResult<()> {
    if decoded_proof.short_response_vector().len() != proof_encoding.short_response_vector_length {
        return Err(invalid_quadratic_challenge(
            "quadratic short response length does not match the proof profile",
        ));
    }
    if decoded_proof.randomness_response_vector().len()
        != proof_encoding.randomness_response_vector_length
    {
        return Err(invalid_quadratic_challenge(
            "quadratic randomness response length does not match the proof profile",
        ));
    }
    if decoded_proof.commitment_target_vector().len()
        != proof_encoding.target_commitment_vector_length
    {
        return Err(invalid_quadratic_challenge(
            "quadratic target vector length does not match the proof profile",
        ));
    }
    if many_quadratic_fold.folded_equation.dimension()
        != 2 * (proof_encoding.short_response_vector_length + QUADRATIC_MESSAGE_LENGTH)
    {
        return Err(invalid_quadratic_challenge(
            "folded many-quadratic equation dimension does not match the proof profile",
        ));
    }

    Ok(())
}

fn recover_quadratic_equation_decompression_input(
    ring: PolynomialRing,
    commitment_key_matrix: &PolynomialMatrix,
    opening_key_matrix: &PolynomialMatrix,
    short_response_vector: &PolynomialVector,
    randomness_response_vector: &PolynomialVector,
    shifted_challenge_polynomial: &[u64],
    compressed_commitment_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let commitment_product = commitment_key_matrix.multiply_vector(short_response_vector)?;
    let opening_product = opening_key_matrix.multiply_vector(randomness_response_vector)?;
    let product_sum = commitment_product.add(&opening_product)?;
    let shifted_challenge_commitment = multiply_polynomial_by_vector(
        ring,
        shifted_challenge_polynomial,
        compressed_commitment_vector,
    )?;

    product_sum.sub(&shifted_challenge_commitment)
}

fn recover_quadratic_equation_message_vector(
    ring: PolynomialRing,
    message_key_matrix: &PolynomialMatrix,
    challenge_polynomial: &[u64],
    randomness_response_vector: &PolynomialVector,
    target_commitment_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let message_target_entries = target_commitment_vector.entries()[..QUADRATIC_MESSAGE_LENGTH]
        .iter()
        .map(|target_polynomial| ring.mul_negacyclic(challenge_polynomial, target_polynomial))
        .collect::<CanonicalResult<Vec<_>>>()?;
    let message_target_vector = PolynomialVector::new(ring, message_target_entries)?;
    let message_binding_product = multiply_matrix_row_range_by_vector(
        message_key_matrix,
        0,
        QUADRATIC_MESSAGE_LENGTH,
        randomness_response_vector,
    )?;

    message_target_vector.sub(&message_binding_product)
}

struct LazerDemoQuadraticVerifierPolynomialInput<'input> {
    proof_ring: PolynomialRing,
    challenge_polynomial: &'input [u64],
    folded_equation: &'input super::quadratic_equation::LinearProofQuadraticEquation,
    short_response_vector: &'input PolynomialVector,
    reconstructed_message_vector: &'input PolynomialVector,
    message_key_matrix: &'input PolynomialMatrix,
    randomness_response_vector: &'input PolynomialVector,
    target_commitment_vector: &'input PolynomialVector,
}

fn recover_quadratic_equation_verifier_polynomial(
    input: LazerDemoQuadraticVerifierPolynomialInput<'_>,
) -> CanonicalResult<Vec<u64>> {
    let proof_ring = input.proof_ring;
    let mut verifier_polynomial = input
        .folded_equation
        .constant_term()
        .ok_or_else(|| invalid_quadratic_challenge("folded quadratic equation is missing r0"))?
        .to_vec();
    verifier_polynomial =
        proof_ring.mul_negacyclic(input.challenge_polynomial, &verifier_polynomial)?;

    let witness_vector = build_quadratic_equation_witness_vector(
        proof_ring,
        input.short_response_vector,
        input.reconstructed_message_vector,
    )?;
    let linear_product = dot_sparse_vector_with_dense_vector(
        proof_ring,
        input.folded_equation.linear_terms(),
        &witness_vector,
    )?;
    verifier_polynomial = proof_ring.add(&verifier_polynomial, &linear_product)?;
    verifier_polynomial =
        proof_ring.mul_negacyclic(input.challenge_polynomial, &verifier_polynomial)?;

    let external_target_polynomial = recover_linear_proof_external_target_polynomial(
        proof_ring,
        input.message_key_matrix,
        input.challenge_polynomial,
        input.randomness_response_vector,
        input.target_commitment_vector,
        input.reconstructed_message_vector,
    )?;
    verifier_polynomial = proof_ring.sub(&verifier_polynomial, &external_target_polynomial)?;

    let quadratic_matrix_product = input
        .folded_equation
        .quadratic_terms()
        .multiply_vector(&witness_vector)?;
    let quadratic_product =
        dot_polynomial_vectors(proof_ring, &witness_vector, &quadratic_matrix_product)?;
    proof_ring.add(&verifier_polynomial, &quadratic_product)
}

fn build_quadratic_equation_witness_vector(
    ring: PolynomialRing,
    short_response_vector: &PolynomialVector,
    reconstructed_message_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let mut witness_entries =
        Vec::with_capacity(2 * (short_response_vector.len() + QUADRATIC_MESSAGE_LENGTH));
    for short_response_polynomial in short_response_vector.entries() {
        witness_entries.push(short_response_polynomial.clone());
        witness_entries.push(ring.automorphism(short_response_polynomial)?);
    }
    for message_polynomial in reconstructed_message_vector.entries() {
        witness_entries.push(message_polynomial.clone());
        witness_entries.push(ring.automorphism(message_polynomial)?);
    }

    PolynomialVector::new(ring, witness_entries)
}

fn recover_linear_proof_external_target_polynomial(
    ring: PolynomialRing,
    message_key_matrix: &PolynomialMatrix,
    challenge_polynomial: &[u64],
    randomness_response_vector: &PolynomialVector,
    target_commitment_vector: &PolynomialVector,
    reconstructed_message_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if reconstructed_message_vector.len() != QUADRATIC_MESSAGE_LENGTH {
        return Err(invalid_quadratic_challenge(
            "reconstructed message vector length does not match the demo profile",
        ));
    }

    if target_commitment_vector.len() != QUADRATIC_TARGET_VECTOR_LENGTH {
        return Err(invalid_quadratic_challenge(
            "target commitment vector length does not match the demo profile",
        ));
    }

    let scaled_external_target = ring.mul_negacyclic(
        challenge_polynomial,
        &target_commitment_vector.entries()[QUADRATIC_MESSAGE_LENGTH],
    )?;
    let external_binding_product = multiply_matrix_row_range_by_vector(
        message_key_matrix,
        QUADRATIC_MESSAGE_LENGTH,
        1,
        randomness_response_vector,
    )?;

    ring.sub(
        &scaled_external_target,
        &external_binding_product.entries()[0],
    )
}

fn recover_quadratic_equation_high_bits(
    recovery_input: &[Vec<u64>],
    hint_vector: &[Vec<i64>],
    proof_encoding: &LinearProofEncoding,
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if recovery_input.len() != hint_vector.len() {
        return Err(invalid_quadratic_challenge(
            "quadratic decompression input and hint vector lengths do not match",
        ));
    }

    recovery_input
        .iter()
        .zip(hint_vector)
        .map(|(input_polynomial, hint_polynomial)| {
            if input_polynomial.len() != hint_polynomial.len() {
                return Err(invalid_quadratic_challenge(
                    "quadratic decompression polynomial degrees do not match",
                ));
            }
            input_polynomial
                .iter()
                .zip(hint_polynomial)
                .map(|(coefficient, hint)| {
                    let high_bits =
                        gamma_decompression_high_bits(*coefficient, proof_encoding, proof_profile)?;
                    positive_mod_i128(
                        high_bits.checked_add(i128::from(*hint)).ok_or_else(|| {
                            invalid_quadratic_challenge("hint addition overflowed")
                        })?,
                        proof_profile.decompression_modulus,
                    )
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect()
}

fn gamma_decompression_high_bits(
    coefficient: u64,
    proof_encoding: &LinearProofEncoding,
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<i128> {
    if coefficient >= proof_encoding.coefficient_modulus {
        return Err(invalid_quadratic_challenge(
            "quadratic decompression coefficient is not canonical",
        ));
    }
    let mut low_part = i128::from(coefficient) % proof_profile.decompression_gamma;
    let half_gamma = proof_profile.decompression_gamma / 2;
    if low_part > half_gamma {
        low_part -= proof_profile.decompression_gamma;
    }
    let high_numerator = i128::from(coefficient)
        .checked_sub(low_part)
        .ok_or_else(|| invalid_quadratic_challenge("high-bit subtraction overflowed"))?;

    if high_numerator == i128::from(proof_encoding.coefficient_modulus - 1) {
        Ok(0)
    } else {
        Ok(high_numerator / proof_profile.decompression_gamma)
    }
}

fn compute_quadratic_equation_low_part_l2_squared(
    ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    recovered_high_bits: &[Vec<u64>],
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<u128> {
    if recovery_input.len() != recovered_high_bits.len() {
        return Err(invalid_quadratic_challenge(
            "quadratic low-part vectors have different lengths",
        ));
    }
    let mut squared_sum = 0_u128;
    for (input_polynomial, high_bits_polynomial) in recovery_input.iter().zip(recovered_high_bits) {
        if input_polynomial.len() != ring.degree() || high_bits_polynomial.len() != ring.degree() {
            return Err(invalid_quadratic_challenge(
                "quadratic low-part polynomial degree does not match the proof ring",
            ));
        }
        for (input_coefficient, high_bits_coefficient) in
            input_polynomial.iter().zip(high_bits_polynomial)
        {
            let low_part = positive_mod_u64_modulus(
                i128::from(*input_coefficient)
                    .checked_sub(
                        proof_profile
                            .decompression_gamma
                            .checked_mul(i128::from(*high_bits_coefficient))
                            .ok_or_else(|| {
                                invalid_quadratic_challenge("low-part multiplication overflowed")
                            })?,
                    )
                    .ok_or_else(|| {
                        invalid_quadratic_challenge("low-part subtraction overflowed")
                    })?,
                ring.modulus(),
            )?;
            let centered_abs = u128::from(ring.centered_abs(low_part)?);
            squared_sum = squared_sum
                .checked_add(
                    centered_abs
                        .checked_mul(centered_abs)
                        .ok_or_else(|| invalid_quadratic_challenge("low-part square overflowed"))?,
                )
                .ok_or_else(|| invalid_quadratic_challenge("low-part l2 sum overflowed"))?;
        }
    }

    Ok(squared_sum)
}

fn encode_quadratic_challenge_input(
    ring: PolynomialRing,
    target_tail_polynomials: &[Vec<u64>],
    verifier_polynomial: &[u64],
    recovered_high_bits: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<Vec<u8>> {
    if target_tail_polynomials.len() != 1 {
        return Err(invalid_quadratic_challenge(
            "quadratic challenge target tail must contain the external target polynomial",
        ));
    }
    let mut writer = QuadraticChallengeBitWriter::new();
    for polynomial in target_tail_polynomials {
        encode_uniform_polynomial(
            &mut writer,
            polynomial,
            ring.modulus(),
            proof_encoding.full_size_coefficient_bit_length,
        )?;
    }
    encode_uniform_polynomial(
        &mut writer,
        verifier_polynomial,
        ring.modulus(),
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    for polynomial in recovered_high_bits {
        encode_uniform_polynomial(
            &mut writer,
            polynomial,
            u64::try_from(proof_profile.decompression_modulus).map_err(|_| {
                invalid_quadratic_challenge("decompression modulus does not fit in u64")
            })?,
            proof_profile.decompression_log2_modulus,
        )?;
    }

    writer.finish()
}

fn encode_uniform_polynomial(
    writer: &mut QuadraticChallengeBitWriter,
    polynomial: &[u64],
    modulus: u64,
    bit_length: usize,
) -> CanonicalResult<()> {
    if polynomial.len() != LINEAR_PROOF_PROOF_RING_DEGREE {
        return Err(invalid_quadratic_challenge(
            "quadratic challenge polynomial degree does not match the proof ring",
        ));
    }
    for coefficient in polynomial {
        if *coefficient >= modulus {
            return Err(invalid_quadratic_challenge(
                "quadratic challenge coefficient is not canonical",
            ));
        }
        writer.write_unsigned_little_endian_bits(*coefficient, bit_length)?;
    }

    Ok(())
}

fn signed_polynomial_vector_to_canonical(
    ring: PolynomialRing,
    polynomials: &[Vec<i64>],
) -> CanonicalResult<PolynomialVector> {
    let canonical_polynomials = polynomials
        .iter()
        .map(|polynomial| {
            if polynomial.len() != ring.degree() {
                return Err(invalid_quadratic_challenge(
                    "signed polynomial degree does not match the proof ring",
                ));
            }
            polynomial
                .iter()
                .map(|coefficient| {
                    positive_mod_u64_modulus(i128::from(*coefficient), ring.modulus())
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(ring, canonical_polynomials)
}

fn challenge_polynomial_to_canonical_proof_ring(
    ring: PolynomialRing,
    centered_coefficients: &[i64],
) -> CanonicalResult<Vec<u64>> {
    if centered_coefficients.len() != ring.degree() {
        return Err(invalid_quadratic_challenge(
            "challenge polynomial degree does not match the proof ring",
        ));
    }

    centered_coefficients
        .iter()
        .map(|coefficient| positive_mod_u64_modulus(i128::from(*coefficient), ring.modulus()))
        .collect()
}

fn multiply_polynomial_by_power_of_two(
    ring: PolynomialRing,
    polynomial: &[u64],
    shift: usize,
) -> CanonicalResult<Vec<u64>> {
    let multiplier =
        1_u64
            .checked_shl(u32::try_from(shift).map_err(|_| {
                invalid_quadratic_challenge("power-of-two shift does not fit in u32")
            })?)
            .ok_or_else(|| invalid_quadratic_challenge("power-of-two shift overflowed"))?;

    ring.scale(multiplier, polynomial)
}

fn multiply_polynomial_by_vector(
    ring: PolynomialRing,
    polynomial: &[u64],
    vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    if vector.ring() != ring {
        return Err(invalid_quadratic_challenge(
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

fn multiply_matrix_row_range_by_vector(
    matrix: &PolynomialMatrix,
    row_start: usize,
    row_count: usize,
    vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    if matrix.ring() != vector.ring() {
        return Err(invalid_quadratic_challenge(
            "matrix/vector multiplication rings do not match",
        ));
    }
    if matrix.columns() != vector.len() {
        return Err(invalid_quadratic_challenge(
            "matrix column count does not match vector length",
        ));
    }
    if row_start
        .checked_add(row_count)
        .ok_or_else(|| invalid_quadratic_challenge("matrix row range overflowed"))?
        > matrix.rows()
    {
        return Err(invalid_quadratic_challenge(
            "matrix row range is outside the matrix",
        ));
    }

    let ring = matrix.ring();
    let mut output_entries = Vec::with_capacity(row_count);
    for row_index in row_start..row_start + row_count {
        let mut row_sum = vec![0_u64; ring.degree()];
        for column_index in 0..matrix.columns() {
            let product = ring.mul_negacyclic(
                matrix.entry(row_index, column_index)?,
                &vector.entries()[column_index],
            )?;
            row_sum = ring.add(&row_sum, &product)?;
        }
        output_entries.push(row_sum);
    }

    PolynomialVector::new(ring, output_entries)
}

fn dot_sparse_vector_with_dense_vector(
    ring: PolynomialRing,
    sparse_vector: &SparsePolynomialVector,
    dense_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if sparse_vector.ring() != ring || dense_vector.ring() != ring {
        return Err(invalid_quadratic_challenge(
            "sparse dot product rings do not match",
        ));
    }
    if sparse_vector.length() != dense_vector.len() {
        return Err(invalid_quadratic_challenge(
            "sparse dot product vector lengths do not match",
        ));
    }

    let mut output = vec![0_u64; ring.degree()];
    for entry in sparse_vector.entries() {
        let product = ring.mul_negacyclic(
            entry.coefficients(),
            &dense_vector.entries()[entry.position()],
        )?;
        output = ring.add(&output, &product)?;
    }

    Ok(output)
}

fn dot_polynomial_vectors(
    ring: PolynomialRing,
    left_vector: &PolynomialVector,
    right_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if left_vector.ring() != ring || right_vector.ring() != ring {
        return Err(invalid_quadratic_challenge(
            "dense dot product rings do not match",
        ));
    }
    if left_vector.len() != right_vector.len() {
        return Err(invalid_quadratic_challenge(
            "dense dot product vector lengths do not match",
        ));
    }

    let mut output = vec![0_u64; ring.degree()];
    for (left_polynomial, right_polynomial) in
        left_vector.entries().iter().zip(right_vector.entries())
    {
        let product = ring.mul_negacyclic(left_polynomial, right_polynomial)?;
        output = ring.add(&output, &product)?;
    }

    Ok(output)
}

fn signed_polynomial_l2_squared(polynomials: &[Vec<i64>]) -> CanonicalResult<u128> {
    let mut squared_sum = 0_u128;
    for polynomial in polynomials {
        for coefficient in polynomial {
            let absolute_value = u128::from(coefficient.unsigned_abs());
            squared_sum = squared_sum
                .checked_add(absolute_value.checked_mul(absolute_value).ok_or_else(|| {
                    invalid_quadratic_challenge("signed coefficient square overflowed")
                })?)
                .ok_or_else(|| invalid_quadratic_challenge("signed l2 sum overflowed"))?;
        }
    }

    Ok(squared_sum)
}

fn signed_polynomial_infinity_norm(polynomials: &[Vec<i64>]) -> CanonicalResult<u128> {
    let mut maximum = 0_u128;
    for coefficient in polynomials.iter().flatten() {
        maximum = maximum.max(u128::from(coefficient.unsigned_abs()));
    }

    Ok(maximum)
}

fn short_response_l2_bound_squared(
    proof_encoding: &LinearProofEncoding,
    proof_profile: super::linear_proof_parameters::LinearProofProfile,
) -> CanonicalResult<u128> {
    let base = 2_u128
        .checked_mul(proof_encoding.short_response_vector_length as u128)
        .and_then(|value| value.checked_mul(proof_encoding.ring_degree as u128))
        .and_then(|value| value.checked_mul(proof_profile.short_response_bound_scale_numerator))
        .ok_or_else(|| invalid_quadratic_challenge("short response bound base overflowed"))?;
    let scaled = base
        .checked_mul(
            1_u128
                .checked_shl(
                    u32::try_from(2 * proof_encoding.short_response_log2_standard_deviation)
                        .map_err(|_| {
                            invalid_quadratic_challenge(
                                "short response bound shift does not fit in u32",
                            )
                        })?,
                )
                .ok_or_else(|| {
                    invalid_quadratic_challenge("short response bound shift overflowed")
                })?,
        )
        .ok_or_else(|| invalid_quadratic_challenge("short response bound overflowed"))?;

    Ok(scaled / proof_profile.short_response_bound_scale_denominator)
}

fn positive_mod_u64_modulus(value: i128, modulus: u64) -> CanonicalResult<u64> {
    positive_mod_i128(value, i128::from(modulus))
}

fn positive_mod_i128(value: i128, modulus: i128) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_quadratic_challenge(
            "positive modulus must be greater than one",
        ));
    }
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }
    u64::try_from(reduced)
        .map_err(|_| invalid_quadratic_challenge("positive modular reduction does not fit in u64"))
}

struct QuadraticChallengeBitWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl QuadraticChallengeBitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_quadratic_challenge(
                "quadratic challenge bit must be zero or one",
            ));
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
            return Err(invalid_quadratic_challenge(
                "quadratic challenge bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_quadratic_challenge(
                "quadratic challenge value does not fit in the requested bit length",
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

fn invalid_quadratic_challenge(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        gamma_decompression_high_bits, short_response_l2_bound_squared,
        validate_quadratic_challenge,
    };
    use crate::{
        ballot_privacy::{
            abdlop_commitment::hash_abdlop_commitment,
            linear_proof_parameters::{LinearProofEncoding, LinearProofParameterSet},
            linear_proof_parameters::{
                demo_linear_proof_encoding_contract, linear_proof_profile_for_encoding,
            },
            linear_proof_statement::{
                LinearProofTargetCoefficientRepresentation, derive_linear_statement_transcript,
                derive_transformed_statement_matrix, derive_transformed_target_vector,
            },
            linear_proof_tbox::validate_linear_proof_tbox_public_checks,
            many_quadratic::{
                build_many_quadratic_equations, fold_default_many_quadratic_equations,
            },
            proof_coder::decode_linear_proof,
            tbox_relations::{
                apply_default_tbox_z3_response_relations, apply_default_tbox_z4_response_relations,
                build_default_tbox_prefix_accumulators,
            },
        },
        transcript_core::decode_hex,
    };

    #[test]
    fn gamma_decompression_matches_linear_proof_high_part_rule() {
        let proof_encoding = demo_linear_proof_encoding_contract();
        let proof_profile =
            linear_proof_profile_for_encoding(&proof_encoding).expect("profile should resolve");
        assert_eq!(
            gamma_decompression_high_bits(514_206, &proof_encoding, proof_profile)
                .expect("high bits should compute"),
            1
        );
        assert_eq!(
            gamma_decompression_high_bits(514_206 + 257_103, &proof_encoding, proof_profile)
                .expect("half low part should stay positive"),
            1
        );
        assert_eq!(
            gamma_decompression_high_bits(514_206 + 257_104, &proof_encoding, proof_profile)
                .expect("wrapped low part should become negative"),
            2
        );
    }

    #[test]
    fn short_response_bound_matches_demo_parameters() {
        let proof_encoding = demo_linear_proof_encoding_contract();
        let proof_profile =
            linear_proof_profile_for_encoding(&proof_encoding).expect("profile should resolve");
        assert_eq!(
            short_response_l2_bound_squared(&proof_encoding, proof_profile)
                .expect("bound should compute"),
            43_631_370_169_221
        );
    }

    #[test]
    fn valid_generated_proof_recomputes_quadratic_challenge() {
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
        let parameter_set: LinearProofParameterSet =
            serde_json::from_value(vector_case["parameterSet"].clone())
                .expect("parameter set should deserialize");
        let proof_encoding: LinearProofEncoding =
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
        let decoded_proof =
            decode_linear_proof(&proof_bytes, &proof_encoding).expect("proof should decode");
        let statement_transcript = derive_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("statement transcript should derive");
        let abdlop_commitment_hash = hash_abdlop_commitment(
            &statement_transcript.public_parameters_and_statement_hash,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("commitment hash should derive");
        let tbox_summary = validate_linear_proof_tbox_public_checks(
            &abdlop_commitment_hash,
            &decoded_proof,
            &proof_encoding,
        )
        .expect("tbox public checks should pass");
        let z34_challenge_hash = decode_hash(&tbox_summary.z34_challenge_hash);
        let generator_challenge_hash = decode_hash(&tbox_summary.generator_challenge_hash);
        let transformed_statement_matrix = derive_transformed_statement_matrix(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("transformed statement should derive");
        let transformed_target_vector = derive_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("transformed target should derive");
        let mut tbox_accumulators =
            build_default_tbox_prefix_accumulators(&generator_challenge_hash)
                .expect("prefix accumulators should build");
        apply_default_tbox_z4_response_relations(
            &mut tbox_accumulators,
            &transformed_statement_matrix,
            &transformed_target_vector,
            decoded_proof.infinity_response_vector(),
            &z34_challenge_hash,
        )
        .expect("z4 response relations should build");
        apply_default_tbox_z3_response_relations(
            &mut tbox_accumulators,
            &transformed_statement_matrix,
            decoded_proof.euclidean_response_vector(),
            &z34_challenge_hash,
        )
        .expect("z3 response relations should build");
        let many_quadratic_equations =
            build_many_quadratic_equations(&tbox_accumulators, decoded_proof.hash_mask_vector())
                .expect("many quadratic equations should build");
        let many_quadratic_fold = fold_default_many_quadratic_equations(
            &many_quadratic_equations,
            &generator_challenge_hash,
        )
        .expect("many quadratic equations should fold");

        let summary = validate_quadratic_challenge(
            &generator_challenge_hash,
            &public_randomness,
            &decoded_proof,
            &proof_encoding,
            &many_quadratic_fold,
        )
        .expect("valid generated proof should recompute challenge");

        assert_eq!(summary.recomputed_challenge_hash.len(), 64);
        assert!(summary.short_response_l2_squared <= summary.short_response_l2_bound_squared);
        assert!(summary.low_part_l2_squared <= summary.low_part_l2_bound_squared);
    }

    fn decode_hash(hash_hex: &str) -> [u8; 32] {
        let bytes = decode_hex(hash_hex).expect("hash should decode");
        bytes
            .as_slice()
            .try_into()
            .expect("hash should contain exactly 32 bytes")
    }
}
