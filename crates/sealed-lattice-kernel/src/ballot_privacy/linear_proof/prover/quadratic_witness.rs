use super::*;
pub(super) fn receiver_key_quadratic_message_vector(
    proof_ring: PolynomialRing,
    z34_message_vector: &PolynomialVector,
    hash_mask_blinding_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let mut entries = z34_message_vector.entries().to_vec();
    entries.extend_from_slice(hash_mask_blinding_vector.entries());

    PolynomialVector::new(proof_ring, entries)
}

pub(super) fn build_paired_quadratic_witness_vector(
    proof_ring: PolynomialRing,
    short_entries: &[Vec<u64>],
    message_entries: &[Vec<u64>],
) -> CanonicalResult<PolynomialVector> {
    let mut witness_entries = Vec::with_capacity(2 * (short_entries.len() + message_entries.len()));
    for polynomial in short_entries {
        proof_ring.validate_coefficients(polynomial)?;
        witness_entries.push(polynomial.clone());
        witness_entries.push(proof_ring.automorphism(polynomial)?);
    }
    for polynomial in message_entries {
        proof_ring.validate_coefficients(polynomial)?;
        witness_entries.push(polynomial.clone());
        witness_entries.push(proof_ring.automorphism(polynomial)?);
    }

    PolynomialVector::new(proof_ring, witness_entries)
}

pub(super) fn receiver_key_hash_mask_from_tbox_equations(
    proof_ring: PolynomialRing,
    folded_tbox_equations: &[LinearProofQuadraticEquation],
    tbox_witness: &PolynomialVector,
    tbox_z34_witness: &PolynomialVector,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if folded_tbox_equations.len() < 4 {
        return Err(invalid_prover(
            "receiver-key tbox folding did not produce the expected equations",
        ));
    }
    let mut hash_mask_vector = Vec::with_capacity(RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS);
    for equation in &folded_tbox_equations[..RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS] {
        let evaluated_polynomial = evaluate_quadratic_equation_equation_with_available_witnesses(
            equation,
            tbox_witness,
            tbox_z34_witness,
        )?;
        if evaluated_polynomial[0] != 0 || evaluated_polynomial[proof_ring.degree() / 2] != 0 {
            return Err(invalid_prover(
                "receiver-key hash-mask polynomial violates constrained zero coefficients",
            ));
        }
        hash_mask_vector.push(evaluated_polynomial);
    }
    for equation in &folded_tbox_equations[RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS..] {
        let evaluated_polynomial = evaluate_quadratic_equation_equation_with_available_witnesses(
            equation,
            tbox_witness,
            tbox_z34_witness,
        )?;
        if !is_zero_polynomial(&evaluated_polynomial) {
            return Err(invalid_prover(
                "receiver-key tbox beta relation is not satisfied by the prover witness",
            ));
        }
    }

    Ok(hash_mask_vector)
}

pub(super) fn evaluate_quadratic_equation_equation_with_available_witnesses(
    equation: &LinearProofQuadraticEquation,
    full_tbox_witness: &PolynomialVector,
    z34_tbox_witness: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if equation.dimension() == full_tbox_witness.len() {
        evaluate_quadratic_equation_equation(equation, full_tbox_witness)
    } else if equation.dimension() == z34_tbox_witness.len() {
        evaluate_quadratic_equation_equation(equation, z34_tbox_witness)
    } else {
        Err(invalid_prover(format!(
            "quadratic equation witness shape does not match the available receiver-key tbox witnesses: full {}, z34 {}, relation {}",
            full_tbox_witness.len(),
            z34_tbox_witness.len(),
            equation.dimension()
        )))
    }
}

pub(super) fn evaluate_quadratic_equation_equation(
    equation: &LinearProofQuadraticEquation,
    witness: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    let proof_ring = equation.ring();
    if witness.ring() != proof_ring || witness.len() != equation.dimension() {
        return Err(invalid_prover(format!(
            "quadratic equation witness shape does not match the relation: witness {}, relation {}",
            witness.len(),
            equation.dimension()
        )));
    }
    let mut evaluated_polynomial = equation
        .constant_term()
        .map(<[u64]>::to_vec)
        .unwrap_or_else(|| vec![0_u64; proof_ring.degree()]);
    let linear_product =
        dot_sparse_vector_with_dense_vector(proof_ring, equation.linear_terms(), witness)?;
    proof_ring.add_assign(&mut evaluated_polynomial, &linear_product)?;
    let quadratic_matrix_product = equation.quadratic_terms().multiply_vector(witness)?;
    let quadratic_product = dot_polynomial_vectors(proof_ring, witness, &quadratic_matrix_product)?;

    proof_ring.add_assign(&mut evaluated_polynomial, &quadratic_product)?;

    Ok(evaluated_polynomial)
}

pub(super) fn dot_sparse_vector_with_dense_vector(
    proof_ring: PolynomialRing,
    sparse_vector: &super::sparse_polynomial_vector::SparsePolynomialVector,
    dense_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if sparse_vector.ring() != proof_ring || dense_vector.ring() != proof_ring {
        return Err(invalid_prover("sparse dot product rings do not match"));
    }
    if sparse_vector.length() != dense_vector.len() {
        return Err(invalid_prover(
            "sparse dot product vector lengths do not match",
        ));
    }
    let mut output = vec![0_u64; proof_ring.degree()];
    for entry in sparse_vector.entries() {
        proof_ring.mul_negacyclic_accumulate(
            &mut output,
            entry.coefficients(),
            &dense_vector.entries()[entry.position()],
        )?;
    }

    Ok(output)
}

pub(super) fn dot_polynomial_vectors(
    proof_ring: PolynomialRing,
    left_vector: &PolynomialVector,
    right_vector: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if left_vector.ring() != proof_ring || right_vector.ring() != proof_ring {
        return Err(invalid_prover("dense dot product rings do not match"));
    }
    if left_vector.len() != right_vector.len() {
        return Err(invalid_prover(
            "dense dot product vector lengths do not match",
        ));
    }
    let mut output = vec![0_u64; proof_ring.degree()];
    for (left_polynomial, right_polynomial) in
        left_vector.entries().iter().zip(right_vector.entries())
    {
        proof_ring.mul_negacyclic_accumulate(&mut output, left_polynomial, right_polynomial)?;
    }

    Ok(output)
}

pub(super) fn multiply_polynomial_by_vector(
    proof_ring: PolynomialRing,
    polynomial: &[u64],
    vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    proof_ring.validate_coefficients(polynomial)?;
    if vector.ring() != proof_ring {
        return Err(invalid_prover(
            "polynomial/vector multiplication rings do not match",
        ));
    }
    let entries = vector
        .entries()
        .iter()
        .map(|entry| proof_ring.mul_negacyclic(polynomial, entry))
        .collect::<CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(proof_ring, entries)
}

pub(super) fn signed_polynomial_to_canonical(
    proof_ring: PolynomialRing,
    polynomial: &[i64],
) -> CanonicalResult<Vec<u64>> {
    if polynomial.len() != proof_ring.degree() {
        return Err(invalid_prover(
            "signed polynomial degree does not match the proof ring",
        ));
    }
    polynomial
        .iter()
        .map(|coefficient| positive_mod_i128(i128::from(*coefficient), proof_ring.modulus()))
        .collect()
}

pub(super) fn canonical_vector_to_centered_entries(
    proof_ring: PolynomialRing,
    entries: &[Vec<u64>],
) -> CanonicalResult<Vec<Vec<i64>>> {
    entries
        .iter()
        .map(|polynomial| {
            if polynomial.len() != proof_ring.degree() {
                return Err(invalid_prover(
                    "canonical polynomial degree does not match the proof ring",
                ));
            }
            polynomial
                .iter()
                .map(|coefficient| canonical_coefficient_to_centered_i64(proof_ring, *coefficient))
                .collect()
        })
        .collect()
}

pub(super) fn canonical_coefficient_to_centered_i64(
    proof_ring: PolynomialRing,
    coefficient: u64,
) -> CanonicalResult<i64> {
    if coefficient >= proof_ring.modulus() {
        return Err(invalid_prover(
            "coefficient is not canonical for the proof ring",
        ));
    }
    if coefficient <= proof_ring.modulus() / 2 {
        i64::try_from(coefficient)
            .map_err(|_| invalid_prover("centered coefficient does not fit in i64"))
    } else {
        let coefficient_value = i128::from(coefficient);
        let modulus_value = i128::from(proof_ring.modulus());
        i64::try_from(coefficient_value - modulus_value)
            .map_err(|_| invalid_prover("centered coefficient does not fit in i64"))
    }
}

pub(super) fn split_flattened_signed_polynomials(
    flattened_coefficients: Vec<i64>,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    flattened_coefficients
        .chunks_exact(ring_degree)
        .map(<[i64]>::to_vec)
        .collect()
}

pub(super) fn make_zero_high_bits_hint(
    proof_ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<Vec<i64>>> {
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    let decompression_modulus = proof_profile.decompression_modulus;
    recovery_input
        .iter()
        .map(|polynomial| {
            if polynomial.len() != proof_ring.degree() {
                return Err(invalid_prover(
                    "recovery polynomial degree does not match the proof ring",
                ));
            }
            polynomial
                .iter()
                .map(|coefficient| {
                    let high_bits = gamma_decompression_high_bits(*coefficient, proof_encoding)?;
                    let centered_hint = if high_bits == 0 {
                        0
                    } else if high_bits * 2 <= decompression_modulus {
                        -high_bits
                    } else {
                        decompression_modulus - high_bits
                    };
                    i64::try_from(centered_hint)
                        .map_err(|_| invalid_prover("hint coefficient does not fit in i64"))
                })
                .collect()
        })
        .collect()
}

pub(super) fn validate_zero_high_bits_low_part(
    proof_ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<()> {
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    let mut squared_sum = 0_u128;
    for polynomial in recovery_input {
        if polynomial.len() != proof_ring.degree() {
            return Err(invalid_prover(
                "recovery polynomial degree does not match the proof ring",
            ));
        }
        for coefficient in polynomial {
            let centered_abs = u128::from(proof_ring.centered_abs(*coefficient)?);
            squared_sum = squared_sum
                .checked_add(
                    centered_abs
                        .checked_mul(centered_abs)
                        .ok_or_else(|| invalid_prover("low-part square overflowed"))?,
                )
                .ok_or_else(|| invalid_prover("low-part l2 norm overflowed"))?;
        }
    }
    if squared_sum > proof_profile.decompression_low_part_bound_squared {
        return Err(invalid_prover(
            "receiver-key decompression low part exceeds the proof profile bound",
        ));
    }

    Ok(())
}

pub(super) fn gamma_decompression_high_bits(
    coefficient: u64,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<i128> {
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    if coefficient >= proof_encoding.coefficient_modulus {
        return Err(invalid_prover("decompression coefficient is not canonical"));
    }
    let mut low_part = i128::from(coefficient) % proof_profile.decompression_gamma;
    let half_gamma = proof_profile.decompression_gamma / 2;
    if low_part > half_gamma {
        low_part -= proof_profile.decompression_gamma;
    }
    let high_numerator = i128::from(coefficient)
        .checked_sub(low_part)
        .ok_or_else(|| invalid_prover("decompression high-bit subtraction overflowed"))?;
    if high_numerator == i128::from(proof_encoding.coefficient_modulus - 1) {
        Ok(0)
    } else {
        Ok(high_numerator / proof_profile.decompression_gamma)
    }
}

pub(super) fn encode_quadratic_challenge_input_for_hash(
    proof_ring: PolynomialRing,
    target_tail_polynomials: &[Vec<u64>],
    verifier_polynomial: &[u64],
    recovered_high_bits: &[Vec<u64>],
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<Vec<u8>> {
    if target_tail_polynomials.len() != RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS {
        return Err(invalid_prover(
            "quadratic challenge target tail has an unexpected length",
        ));
    }
    let proof_profile = linear_proof_profile_for_encoding(proof_encoding)?;
    let mut writer = ProverBitWriter::new();
    for polynomial in target_tail_polynomials {
        encode_uniform_polynomial_for_hash(
            &mut writer,
            polynomial,
            proof_ring,
            proof_ring.modulus(),
            proof_encoding.full_size_coefficient_bit_length,
        )?;
    }
    encode_uniform_polynomial_for_hash(
        &mut writer,
        verifier_polynomial,
        proof_ring,
        proof_ring.modulus(),
        proof_encoding.full_size_coefficient_bit_length,
    )?;
    let high_bits_modulus = u64::try_from(proof_profile.decompression_modulus)
        .map_err(|_| invalid_prover("decompression modulus does not fit in u64"))?;
    for polynomial in recovered_high_bits {
        encode_uniform_polynomial_for_hash(
            &mut writer,
            polynomial,
            proof_ring,
            high_bits_modulus,
            proof_profile.decompression_log2_modulus,
        )?;
    }

    writer.finish()
}

pub(super) fn encode_uniform_polynomial_vector_for_hash(
    polynomials: &[Vec<u64>],
    proof_ring: PolynomialRing,
    coefficient_bit_length: usize,
) -> CanonicalResult<Vec<u8>> {
    let mut writer = ProverBitWriter::new();
    for polynomial in polynomials {
        encode_uniform_polynomial_for_hash(
            &mut writer,
            polynomial,
            proof_ring,
            proof_ring.modulus(),
            coefficient_bit_length,
        )?;
    }

    writer.finish()
}

pub(super) fn encode_uniform_polynomial_for_hash(
    writer: &mut ProverBitWriter,
    polynomial: &[u64],
    proof_ring: PolynomialRing,
    modulus: u64,
    bit_length: usize,
) -> CanonicalResult<()> {
    if polynomial.len() != proof_ring.degree() {
        return Err(invalid_prover(
            "hash polynomial degree does not match the proof ring",
        ));
    }
    for coefficient in polynomial {
        if *coefficient >= modulus {
            return Err(invalid_prover(
                "hash polynomial coefficient is not canonical",
            ));
        }
        writer.write_unsigned_little_endian_bits(*coefficient, bit_length)?;
    }

    Ok(())
}

pub(super) struct ProverBitWriter {
    output: Vec<u8>,
    bit_offset: usize,
}

impl ProverBitWriter {
    fn new() -> Self {
        Self {
            output: Vec::new(),
            bit_offset: 0,
        }
    }

    fn write_bit(&mut self, bit: u8) -> CanonicalResult<()> {
        if bit > 1 {
            return Err(invalid_prover("hash bit must be zero or one"));
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
            return Err(invalid_prover(
                "hash bit length must be between one and sixty-three",
            ));
        }
        if value >= (1_u64 << bit_count) {
            return Err(invalid_prover(
                "hash value does not fit in the requested bit length",
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

pub(super) fn read_bit(bytes: &[u8], bit_index: usize) -> CanonicalResult<u8> {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return Err(invalid_prover("bit stream ended early"));
    }
    Ok((bytes[byte_index] >> (bit_index % 8)) & 1)
}

pub(super) fn validate_source_witness_shape(
    parameter_set: &LinearProofParameterSet,
    source_witness_coefficients: &[Vec<i64>],
) -> CanonicalResult<()> {
    if source_witness_coefficients.len() != parameter_set.statement_columns {
        return Err(invalid_prover(
            "linear prover source witness length does not match the parameter set",
        ));
    }
    let centered_limit = i64::try_from(parameter_set.coefficient_modulus / 2)
        .map_err(|_| invalid_prover("linear prover source modulus does not fit in i64"))?;
    for polynomial in source_witness_coefficients {
        if polynomial.len() != parameter_set.ring_degree {
            return Err(invalid_prover(
                "linear prover source witness polynomial degree does not match the parameter set",
            ));
        }
        if polynomial
            .iter()
            .any(|coefficient| coefficient.unsigned_abs() > centered_limit as u64)
        {
            return Err(invalid_prover(
                "linear prover source witness coefficient is not a centered source representative",
            ));
        }
    }

    Ok(())
}

pub(super) fn validate_streamed_statement_shape<Statement>(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    statement: &Statement,
) -> CanonicalResult<()>
where
    Statement: StreamedLinearProofStatement,
{
    source_polynomial_split_factor(parameter_set, proof_encoding)?;
    if statement.source_statement_rows() != parameter_set.statement_rows
        || statement.source_statement_columns() != parameter_set.statement_columns
    {
        return Err(invalid_prover(
            "streamed linear statement shape does not match the parameter set",
        ));
    }
    if statement.target_vector_coefficients().len() != parameter_set.statement_rows {
        return Err(invalid_prover(
            "streamed linear statement target length does not match the parameter set",
        ));
    }

    Ok(())
}

pub(super) fn source_statement_matrix(
    parameter_set: &LinearProofParameterSet,
    statement_matrix_coefficients: &[Vec<Vec<u64>>],
) -> CanonicalResult<PolynomialMatrix> {
    if statement_matrix_coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_prover(
            "linear prover statement matrix row count does not match the parameter set",
        ));
    }
    let mut entries =
        Vec::with_capacity(parameter_set.statement_rows * parameter_set.statement_columns);
    for row in statement_matrix_coefficients {
        if row.len() != parameter_set.statement_columns {
            return Err(invalid_prover(
                "linear prover statement matrix column count does not match the parameter set",
            ));
        }
        entries.extend(row.iter().cloned());
    }

    PolynomialMatrix::new(
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?,
        parameter_set.statement_rows,
        parameter_set.statement_columns,
        entries,
    )
}

pub(super) fn source_target_vector(
    parameter_set: &LinearProofParameterSet,
    target_vector_coefficients: &[Vec<u64>],
) -> CanonicalResult<PolynomialVector> {
    if target_vector_coefficients.len() != parameter_set.statement_rows {
        return Err(invalid_prover(
            "linear prover target vector length does not match the parameter set",
        ));
    }

    PolynomialVector::new(
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?,
        target_vector_coefficients.to_vec(),
    )
}

pub(super) fn source_witness_to_canonical_vector(
    parameter_set: &LinearProofParameterSet,
    source_witness_coefficients: &[Vec<i64>],
) -> CanonicalResult<PolynomialVector> {
    let source_ring =
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)?;
    let entries = source_witness_coefficients
        .iter()
        .map(|polynomial| {
            polynomial
                .iter()
                .map(|coefficient| {
                    positive_mod_i128(i128::from(*coefficient), parameter_set.coefficient_modulus)
                })
                .collect::<CanonicalResult<Vec<_>>>()
        })
        .collect::<CanonicalResult<Vec<_>>>()?;

    PolynomialVector::new(source_ring, entries)
}

pub(super) fn source_witness_l2_squared(
    source_witness_coefficients: &[Vec<i64>],
) -> CanonicalResult<u128> {
    let mut sum = 0_u128;
    for polynomial in source_witness_coefficients {
        for coefficient in polynomial {
            let absolute_value = u128::from(coefficient.unsigned_abs());
            sum = sum
                .checked_add(
                    absolute_value
                        .checked_mul(absolute_value)
                        .ok_or_else(|| invalid_prover("linear prover witness square overflowed"))?,
                )
                .ok_or_else(|| invalid_prover("linear prover witness l2 norm overflowed"))?;
        }
    }

    Ok(sum)
}

pub(super) fn transform_source_witness_to_proof_ring(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LinearProofEncoding,
    source_witness_coefficients: &[Vec<i64>],
) -> CanonicalResult<Vec<Vec<u64>>> {
    let source_polynomial_split_factor =
        source_polynomial_split_factor(parameter_set, proof_encoding)?;
    let proof_modulus = proof_encoding.coefficient_modulus;
    let mut transformed_entries = Vec::with_capacity(
        parameter_set
            .statement_columns
            .checked_mul(source_polynomial_split_factor)
            .ok_or_else(|| invalid_prover("linear prover witness split length overflowed"))?,
    );
    for source_polynomial in source_witness_coefficients {
        let split_polynomials = split_signed_polynomial_into_proof_ring(
            source_polynomial,
            source_polynomial_split_factor,
        )?;
        for split_polynomial in split_polynomials {
            transformed_entries.push(
                split_polynomial
                    .iter()
                    .map(|coefficient| positive_mod_i128(*coefficient, proof_modulus))
                    .collect::<CanonicalResult<Vec<_>>>()?,
            );
        }
    }

    Ok(transformed_entries)
}

// Strided decomposition of one degree-256 source polynomial into k degree-64
// proof polynomials, interleaving by split_factor*coeff_index + component_index.
// The verifier recombines with the same stride, so this layout is load-bearing.
pub(super) fn split_signed_polynomial_into_proof_ring(
    source_polynomial: &[i64],
    source_polynomial_split_factor: usize,
) -> CanonicalResult<Vec<Vec<i128>>> {
    if source_polynomial_split_factor == 0
        || !source_polynomial
            .len()
            .is_multiple_of(source_polynomial_split_factor)
    {
        return Err(invalid_prover(
            "linear prover witness source degree does not decompose evenly",
        ));
    }
    let proof_ring_degree = source_polynomial.len() / source_polynomial_split_factor;
    let mut split_polynomials =
        vec![vec![0_i128; proof_ring_degree]; source_polynomial_split_factor];

    for (component_index, split_polynomial) in split_polynomials.iter_mut().enumerate() {
        for (coefficient_index, coefficient) in split_polynomial.iter_mut().enumerate() {
            *coefficient = i128::from(
                source_polynomial
                    [source_polynomial_split_factor * coefficient_index + component_index],
            );
        }
    }

    Ok(split_polynomials)
}

pub(super) fn binary_expansion_polynomial(
    proof_ring: PolynomialRing,
    value: u128,
) -> CanonicalResult<Vec<u64>> {
    let mut polynomial = vec![0_u64; proof_ring.degree()];
    let mut remaining_value = value;
    let mut bit_index = 0_usize;
    while remaining_value > 0 {
        if bit_index >= proof_ring.degree() {
            return Err(invalid_prover(
                "linear prover norm slack does not fit in the proof-ring binary coordinate",
            ));
        }
        polynomial[bit_index] = u64::from((remaining_value & 1) != 0);
        remaining_value >>= 1;
        bit_index += 1;
    }

    Ok(polynomial)
}

pub(super) fn sample_abdlop_opening_randomness_vector(
    proof_ring: PolynomialRing,
    proof_encoding: &LinearProofEncoding,
    seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> CanonicalResult<PolynomialVector> {
    let opening_randomness_length = proof_encoding
        .randomness_response_vector_length
        .checked_add(proof_encoding.compressed_commitment_vector_length)
        .ok_or_else(|| invalid_prover("linear prover opening randomness length overflowed"))?;
    let mut entries = Vec::with_capacity(opening_randomness_length);
    for polynomial_index in 0..opening_randomness_length {
        let domain_separator = u64::try_from(polynomial_index + 1)
            .map_err(|_| invalid_prover("linear prover randomness domain overflowed"))?;
        let sampled_coefficients = sample_linear_proof_uniform_u64_values(
            proof_ring.degree(),
            ABDLOP_OPENING_RANDOMNESS_BOUND_MODULUS,
            ABDLOP_OPENING_RANDOMNESS_BOUND_BIT_LENGTH,
            seed,
            domain_separator,
        )?;
        // ABDLOP opening randomness is centered ternary {-1, 0, +1}: each sample
        // is drawn mod 3 (0/1/2) and recentred to -1/0/+1 by subtracting 1.
        let polynomial = sampled_coefficients
            .iter()
            .map(|sample| {
                let centered_sample = i128::from(*sample) - 1;
                positive_mod_i128(centered_sample, proof_ring.modulus())
            })
            .collect::<CanonicalResult<Vec<_>>>()?;
        entries.push(polynomial);
    }

    PolynomialVector::new(proof_ring, entries)
}

// Dilithium-style Power2Round compression of the ABDLOP commitment: split each
// coefficient into a centered low part in (-base/2, base/2] (the remainder) and
// a high part divided out by base. compression_shift = full_bits - compressed_bits.
pub(super) fn power2round_abdlop_commitment(
    uncompressed_commitment: &PolynomialVector,
    proof_encoding: &LinearProofEncoding,
) -> CanonicalResult<(PolynomialVector, PolynomialVector)> {
    let proof_ring = uncompressed_commitment.ring();
    if proof_ring.degree() != proof_encoding.ring_degree
        || proof_ring.modulus() != proof_encoding.coefficient_modulus
    {
        return Err(invalid_prover(
            "linear prover ABDLOP commitment ring does not match the proof encoding",
        ));
    }
    if uncompressed_commitment.len() != proof_encoding.compressed_commitment_vector_length {
        return Err(invalid_prover(
            "linear prover ABDLOP commitment length does not match the proof encoding",
        ));
    }
    let compression_shift = proof_encoding
        .full_size_coefficient_bit_length
        .checked_sub(proof_encoding.compressed_coefficient_bit_length)
        .ok_or_else(|| invalid_prover("linear prover compression bit lengths are inconsistent"))?;
    let compression_base = 1_i128
        .checked_shl(
            u32::try_from(compression_shift)
                .map_err(|_| invalid_prover("linear prover compression shift is too large"))?,
        )
        .ok_or_else(|| invalid_prover("linear prover compression base overflowed"))?;
    let half_compression_base = compression_base / 2;
    let compressed_modulus = 1_u64
        .checked_shl(
            u32::try_from(proof_encoding.compressed_coefficient_bit_length)
                .map_err(|_| invalid_prover("linear prover compressed bit length is too large"))?,
        )
        .ok_or_else(|| invalid_prover("linear prover compressed modulus overflowed"))?;

    let mut compressed_entries = Vec::with_capacity(uncompressed_commitment.len());
    let mut remainder_entries = Vec::with_capacity(uncompressed_commitment.len());
    for polynomial in uncompressed_commitment.entries() {
        let mut compressed_polynomial = Vec::with_capacity(proof_ring.degree());
        let mut remainder_polynomial = Vec::with_capacity(proof_ring.degree());
        for coefficient in polynomial {
            let coefficient = i128::from(*coefficient);
            let mut low_part = coefficient % compression_base;
            if low_part > half_compression_base {
                low_part -= compression_base;
            }
            let high_part = coefficient.checked_sub(low_part).ok_or_else(|| {
                invalid_prover("linear prover power2round subtraction overflowed")
            })? / compression_base;
            if high_part < 0 || high_part >= i128::from(compressed_modulus) {
                return Err(invalid_prover(
                    "linear prover compressed commitment coefficient is outside the encoding range",
                ));
            }
            compressed_polynomial.push(u64::try_from(high_part).map_err(|_| {
                invalid_prover("linear prover compressed coefficient does not fit in u64")
            })?);
            remainder_polynomial.push(positive_mod_i128(
                coefficient
                    .checked_sub(high_part.checked_mul(compression_base).ok_or_else(|| {
                        invalid_prover("linear prover power2round multiplication overflowed")
                    })?)
                    .ok_or_else(|| {
                        invalid_prover("linear prover power2round remainder overflowed")
                    })?,
                proof_ring.modulus(),
            )?);
        }
        compressed_entries.push(compressed_polynomial);
        remainder_entries.push(remainder_polynomial);
    }

    Ok((
        PolynomialVector::new(proof_ring, compressed_entries)?,
        PolynomialVector::new(proof_ring, remainder_entries)?,
    ))
}

pub(super) fn is_zero_polynomial_vector(vector: &PolynomialVector) -> bool {
    vector
        .entries()
        .iter()
        .all(|polynomial| polynomial.iter().all(|coefficient| *coefficient == 0))
}

pub(super) fn is_zero_polynomial(polynomial: &[u64]) -> bool {
    polynomial.iter().all(|coefficient| *coefficient == 0)
}
