use super::*;
use crate::ballot_privacy::tbox_relations::TboxZ4ResponseRelationInputs;
pub(crate) fn generate_sparse_linear_proof(
    input: SparseLinearProverProofInput<'_>,
) -> CanonicalResult<LinearProverProofGeneration> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    let proof_profile = linear_proof_profile_for_encoding(input.proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let statement_transcript =
        derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation(
        input.parameter_set,
        input.proof_encoding,
        input.source_statement_matrix,
        input.target_vector_coefficients,
        input.matrix_coefficient_representation,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let witness_preparation =
        prepare_sparse_linear_prover_witness(SparseLinearProverWitnessInput {
            parameter_set: input.parameter_set,
            proof_encoding: input.proof_encoding,
            source_statement_matrix: input.source_statement_matrix,
            target_vector_coefficients: input.target_vector_coefficients,
            matrix_coefficient_representation: input.matrix_coefficient_representation,
            target_coefficient_representation: input.target_coefficient_representation,
            source_witness_coefficients: input.source_witness_coefficients,
        })?;
    let commitment_preparation = prepare_linear_prover_commitment(LinearProverCommitmentInput {
        proof_encoding: input.proof_encoding,
        public_randomness: input.public_randomness,
        statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
        witness_preparation: &witness_preparation,
        prover_randomness: input.prover_randomness,
    })?;
    let encoded_commitment = encode_compressed_commitment_vector(
        commitment_preparation
            .compressed_commitment_vector()
            .entries(),
        input.proof_encoding,
    )?;
    let abdlop_commitment_hash = shake128_32(&[
        &statement_transcript.public_parameters_and_statement_hash,
        &encoded_commitment,
    ]);
    let public_parameters =
        derive_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
    let short_witness = witness_preparation.short_witness_vector();
    let opening_randomness = commitment_preparation.opening_randomness_vector();
    let opening_randomness_prefix = PolynomialVector::new(
        proof_ring,
        opening_randomness.entries()[..input.proof_encoding.randomness_response_vector_length]
            .to_vec(),
    )?;
    let subprotocol_seeds = shake128_96(&[commitment_preparation.subprotocol_seed()]);
    let mut z34_seed = [0_u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES];
    z34_seed.copy_from_slice(&subprotocol_seeds[..RECEIVER_KEY_PROVER_RANDOMNESS_BYTES]);

    let beta_signs = receiver_key_tbox_beta_signs(&z34_seed);
    let z34_message_vector = receiver_key_z34_message_vector(proof_ring, beta_signs)?;
    let mut target_commitment_vector = receiver_key_target_commitment_prefix(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        &z34_message_vector,
    )?;
    let z34_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let z34_challenge_hash = shake128_32(&[&abdlop_commitment_hash, &z34_challenge_encoding]);
    let transformed_statement_matrix =
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation(
            input.parameter_set,
            input.proof_encoding,
            input.source_statement_matrix,
            input.matrix_coefficient_representation,
        )?;
    let transformed_target_vector = transform_sparse_target_vector_to_proof_ring(
        input.parameter_set,
        input.proof_encoding,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
    )?;
    let transformed_relation_witness = PolynomialVector::new(
        proof_ring,
        short_witness.entries()[..short_witness.len() - 1].to_vec(),
    )?;
    let tbox_z4_secret = transformed_statement_matrix
        .multiply_vector(&transformed_relation_witness)?
        .add(&transformed_target_vector)?;
    let euclidean_response_vector = compute_receiver_key_tbox_z3_response(
        proof_ring,
        short_witness,
        beta_signs.0,
        &z34_challenge_hash,
    )?;
    let infinity_response_vector = if is_zero_polynomial_vector(&tbox_z4_secret) {
        vec![vec![0_i64; proof_ring.degree()]; input.proof_encoding.infinity_response_vector_length]
    } else {
        compute_receiver_key_tbox_z4_response(
            proof_ring,
            &tbox_z4_secret,
            beta_signs.1,
            &z34_challenge_hash,
        )?
    };

    let hash_mask_blinding_vector =
        receiver_key_zero_message_vector(proof_ring, RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS)?;
    let hash_mask_target_commitment = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS,
        &hash_mask_blinding_vector,
    )?;
    target_commitment_vector.extend(hash_mask_target_commitment);
    let generator_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS
            ..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let generator_challenge_hash =
        shake128_32(&[&z34_challenge_hash, &generator_challenge_encoding]);

    let mut tbox_accumulators =
        build_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_tbox_z4_response_relations_sparse(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &transformed_target_vector,
        &infinity_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    apply_tbox_z3_response_relations_sparse(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &euclidean_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    let tbox_witness = build_receiver_key_tbox_witness_vector(
        proof_ring,
        short_witness,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let tbox_z34_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        z34_message_vector.entries(),
    )?;
    let folded_tbox_equations = tbox_accumulators.auto_folded_equations()?;
    let hash_mask_vector = receiver_key_hash_mask_from_tbox_equations(
        proof_ring,
        &folded_tbox_equations,
        &tbox_witness,
        &tbox_z34_witness,
    )?;
    let many_quadratic_equations =
        build_many_quadratic_equations(&tbox_accumulators, &hash_mask_vector)?;
    let many_quadratic_fold = fold_many_quadratic_equations(
        &many_quadratic_equations,
        &generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let quadratic_message_vector = receiver_key_quadratic_message_vector(
        proof_ring,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let quadratic_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        quadratic_message_vector.entries(),
    )?;
    let folded_relation_value = evaluate_quadratic_equation_equation(
        &many_quadratic_fold.folded_equation,
        &quadratic_witness,
    )?;
    if !is_zero_polynomial(&folded_relation_value) {
        return Err(invalid_prover(
            "receiver-key many-quadratic relation is not satisfied by the prover witness",
        ));
    }

    let quadratic_target_tail = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS,
        &receiver_key_zero_message_vector(
            proof_ring,
            RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS,
        )?,
    )?;
    target_commitment_vector.extend(quadratic_target_tail);
    let zero_verifier_polynomial = vec![0_u64; proof_ring.degree()];
    let zero_recovered_high_bits =
        vec![vec![0_u64; proof_ring.degree()]; input.proof_encoding.hint_vector_length];
    let quadratic_challenge_encoding = encode_quadratic_challenge_input_for_hash(
        proof_ring,
        &target_commitment_vector
            [RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS..],
        &zero_verifier_polynomial,
        &zero_recovered_high_bits,
        input.proof_encoding,
    )?;
    let quadratic_challenge_hash =
        shake128_32(&[&generator_challenge_hash, &quadratic_challenge_encoding]);
    let centered_challenge_polynomial = sample_linear_proof_autostable_challenge_coefficients(
        proof_ring.degree(),
        proof_profile.challenge_centered_bound,
        proof_profile.challenge_coefficient_bit_length,
        &quadratic_challenge_hash,
        0,
    )?;
    let challenge_polynomial =
        signed_polynomial_to_canonical(proof_ring, &centered_challenge_polynomial)?;
    let short_response_vector =
        multiply_polynomial_by_vector(proof_ring, &challenge_polynomial, short_witness)?;
    let randomness_response_vector = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        &opening_randomness_prefix,
    )?;
    let recovery_input = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        commitment_preparation.opening_remainder_vector(),
    )?;
    let hint_vector =
        make_zero_high_bits_hint(proof_ring, recovery_input.entries(), input.proof_encoding)?;
    validate_zero_high_bits_low_part(proof_ring, recovery_input.entries(), input.proof_encoding)?;

    let proof_bytes = encode_linear_proof_components(
        LinearProofComponents {
            commitment_target_vector: target_commitment_vector,
            hash_mask_vector,
            compressed_commitment_vector: commitment_preparation
                .compressed_commitment_vector()
                .entries()
                .to_vec(),
            centered_challenge_polynomial,
            hint_vector,
            short_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                short_response_vector.entries(),
            )?,
            randomness_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                randomness_response_vector.entries(),
            )?,
            euclidean_response_vector,
            infinity_response_vector,
        },
        input.proof_encoding,
    )?;
    let summary = LinearProverProofSummary {
        proof_size_bytes: proof_bytes.len(),
        abdlop_commitment_hash_hex: to_hex(&abdlop_commitment_hash),
        z34_challenge_hash_hex: to_hex(&z34_challenge_hash),
        generator_challenge_hash_hex: to_hex(&generator_challenge_hash),
        quadratic_challenge_hash_hex: to_hex(&quadratic_challenge_hash),
    };

    Ok(LinearProverProofGeneration {
        proof_bytes,
        summary,
    })
}

pub(crate) fn generate_streamed_linear_proof<Statement>(
    input: StreamedLinearProverProofInput<'_, Statement>,
) -> CanonicalResult<LinearProverProofGeneration>
where
    Statement: StreamedLinearProofStatement,
{
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_streamed_statement_shape(input.parameter_set, input.proof_encoding, input.statement)?;
    let proof_profile = linear_proof_profile_for_encoding(input.proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let source_polynomial_split_factor =
        source_polynomial_split_factor(input.parameter_set, input.proof_encoding)?;
    let transformed_statement_rows = input
        .parameter_set
        .statement_rows
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_prover("linear prover transformed row count overflowed"))?;
    let transformed_statement_columns = input
        .parameter_set
        .statement_columns
        .checked_mul(source_polynomial_split_factor)
        .ok_or_else(|| invalid_prover("linear prover transformed column count overflowed"))?;
    let statement_transcript = input.statement.derive_statement_transcript(
        input.parameter_set,
        input.proof_encoding,
        input.matrix_coefficient_representation,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let witness_preparation = prepare_streamed_linear_prover_witness(
        input.parameter_set,
        input.proof_encoding,
        input.statement,
        input.matrix_coefficient_representation,
        input.target_coefficient_representation,
        input.source_witness_coefficients,
    )?;
    let commitment_preparation = prepare_linear_prover_commitment(LinearProverCommitmentInput {
        proof_encoding: input.proof_encoding,
        public_randomness: input.public_randomness,
        statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
        witness_preparation: &witness_preparation,
        prover_randomness: input.prover_randomness,
    })?;
    let encoded_commitment = encode_compressed_commitment_vector(
        commitment_preparation
            .compressed_commitment_vector()
            .entries(),
        input.proof_encoding,
    )?;
    let abdlop_commitment_hash = shake128_32(&[
        &statement_transcript.public_parameters_and_statement_hash,
        &encoded_commitment,
    ]);
    let public_parameters =
        derive_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
    let short_witness = witness_preparation.short_witness_vector();
    let opening_randomness = commitment_preparation.opening_randomness_vector();
    let opening_randomness_prefix = PolynomialVector::new(
        proof_ring,
        opening_randomness.entries()[..input.proof_encoding.randomness_response_vector_length]
            .to_vec(),
    )?;
    let subprotocol_seeds = shake128_96(&[commitment_preparation.subprotocol_seed()]);
    let mut z34_seed = [0_u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES];
    z34_seed.copy_from_slice(&subprotocol_seeds[..RECEIVER_KEY_PROVER_RANDOMNESS_BYTES]);

    let beta_signs = receiver_key_tbox_beta_signs(&z34_seed);
    let z34_message_vector = receiver_key_z34_message_vector(proof_ring, beta_signs)?;
    let mut target_commitment_vector = receiver_key_target_commitment_prefix(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        &z34_message_vector,
    )?;
    let z34_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let z34_challenge_hash = shake128_32(&[&abdlop_commitment_hash, &z34_challenge_encoding]);
    let transformed_target_vector = input.statement.transformed_target_vector(
        input.parameter_set,
        input.proof_encoding,
        input.target_coefficient_representation,
    )?;
    let transformed_relation_witness = PolynomialVector::new(
        proof_ring,
        short_witness.entries()[..short_witness.len() - 1].to_vec(),
    )?;
    let tbox_z4_secret = input.statement.transformed_relation_output(
        input.parameter_set,
        input.proof_encoding,
        input.matrix_coefficient_representation,
        &transformed_relation_witness,
        &transformed_target_vector,
    )?;
    let euclidean_response_vector = compute_receiver_key_tbox_z3_response(
        proof_ring,
        short_witness,
        beta_signs.0,
        &z34_challenge_hash,
    )?;
    let infinity_response_vector = if is_zero_polynomial_vector(&tbox_z4_secret) {
        vec![vec![0_i64; proof_ring.degree()]; input.proof_encoding.infinity_response_vector_length]
    } else {
        compute_receiver_key_tbox_z4_response(
            proof_ring,
            &tbox_z4_secret,
            beta_signs.1,
            &z34_challenge_hash,
        )?
    };

    let hash_mask_blinding_vector =
        receiver_key_zero_message_vector(proof_ring, RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS)?;
    let hash_mask_target_commitment = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS,
        &hash_mask_blinding_vector,
    )?;
    target_commitment_vector.extend(hash_mask_target_commitment);
    let generator_challenge_encoding = encode_uniform_polynomial_vector_for_hash(
        &target_commitment_vector[RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS
            ..RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS],
        proof_ring,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let generator_challenge_hash =
        shake128_32(&[&z34_challenge_hash, &generator_challenge_encoding]);

    let mut tbox_accumulators =
        build_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_tbox_z4_response_relations_with_product_builder(
        &mut tbox_accumulators,
        TboxZ4ResponseRelationInputs {
            transformed_statement_rows,
            transformed_statement_columns,
            transformed_target_vector: &transformed_target_vector,
            infinity_response_vector: &infinity_response_vector,
            challenge_seed: &z34_challenge_hash,
            proof_encoding: input.proof_encoding,
        },
        |product_ring, shifted_rotation_polynomial_matrix| {
            input.statement.build_z4_statement_products(
                product_ring,
                input.parameter_set,
                input.proof_encoding,
                input.matrix_coefficient_representation,
                shifted_rotation_polynomial_matrix,
            )
        },
    )?;
    apply_tbox_z3_response_relations_for_statement_shape(
        &mut tbox_accumulators,
        transformed_statement_rows,
        transformed_statement_columns,
        &euclidean_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    let tbox_witness = build_receiver_key_tbox_witness_vector(
        proof_ring,
        short_witness,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let tbox_z34_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        z34_message_vector.entries(),
    )?;
    let folded_tbox_equations = tbox_accumulators.auto_folded_equations()?;
    let hash_mask_vector = receiver_key_hash_mask_from_tbox_equations(
        proof_ring,
        &folded_tbox_equations,
        &tbox_witness,
        &tbox_z34_witness,
    )?;
    let many_quadratic_equations =
        build_many_quadratic_equations(&tbox_accumulators, &hash_mask_vector)?;
    let many_quadratic_fold = fold_many_quadratic_equations(
        &many_quadratic_equations,
        &generator_challenge_hash,
        input.proof_encoding.full_size_coefficient_bit_length,
    )?;
    let quadratic_message_vector = receiver_key_quadratic_message_vector(
        proof_ring,
        &z34_message_vector,
        &hash_mask_blinding_vector,
    )?;
    let quadratic_witness = build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        quadratic_message_vector.entries(),
    )?;
    let folded_relation_value = evaluate_quadratic_equation_equation(
        &many_quadratic_fold.folded_equation,
        &quadratic_witness,
    )?;
    if !is_zero_polynomial(&folded_relation_value) {
        return Err(invalid_prover(
            "receiver-key many-quadratic relation is not satisfied by the prover witness",
        ));
    }

    let quadratic_target_tail = receiver_key_target_commitment_rows(
        &public_parameters.message_key_matrix,
        &opening_randomness_prefix,
        RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS,
        &receiver_key_zero_message_vector(
            proof_ring,
            RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS,
        )?,
    )?;
    target_commitment_vector.extend(quadratic_target_tail);
    let zero_verifier_polynomial = vec![0_u64; proof_ring.degree()];
    let zero_recovered_high_bits =
        vec![vec![0_u64; proof_ring.degree()]; input.proof_encoding.hint_vector_length];
    let quadratic_challenge_encoding = encode_quadratic_challenge_input_for_hash(
        proof_ring,
        &target_commitment_vector
            [RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS + RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS..],
        &zero_verifier_polynomial,
        &zero_recovered_high_bits,
        input.proof_encoding,
    )?;
    let quadratic_challenge_hash =
        shake128_32(&[&generator_challenge_hash, &quadratic_challenge_encoding]);
    let centered_challenge_polynomial = sample_linear_proof_autostable_challenge_coefficients(
        proof_ring.degree(),
        proof_profile.challenge_centered_bound,
        proof_profile.challenge_coefficient_bit_length,
        &quadratic_challenge_hash,
        0,
    )?;
    let challenge_polynomial =
        signed_polynomial_to_canonical(proof_ring, &centered_challenge_polynomial)?;
    let short_response_vector =
        multiply_polynomial_by_vector(proof_ring, &challenge_polynomial, short_witness)?;
    let randomness_response_vector = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        &opening_randomness_prefix,
    )?;
    let recovery_input = multiply_polynomial_by_vector(
        proof_ring,
        &challenge_polynomial,
        commitment_preparation.opening_remainder_vector(),
    )?;
    let hint_vector =
        make_zero_high_bits_hint(proof_ring, recovery_input.entries(), input.proof_encoding)?;
    validate_zero_high_bits_low_part(proof_ring, recovery_input.entries(), input.proof_encoding)?;

    let proof_bytes = encode_linear_proof_components(
        LinearProofComponents {
            commitment_target_vector: target_commitment_vector,
            hash_mask_vector,
            compressed_commitment_vector: commitment_preparation
                .compressed_commitment_vector()
                .entries()
                .to_vec(),
            centered_challenge_polynomial,
            hint_vector,
            short_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                short_response_vector.entries(),
            )?,
            randomness_response_vector: canonical_vector_to_centered_entries(
                proof_ring,
                randomness_response_vector.entries(),
            )?,
            euclidean_response_vector,
            infinity_response_vector,
        },
        input.proof_encoding,
    )?;
    let summary = LinearProverProofSummary {
        proof_size_bytes: proof_bytes.len(),
        abdlop_commitment_hash_hex: to_hex(&abdlop_commitment_hash),
        z34_challenge_hash_hex: to_hex(&z34_challenge_hash),
        generator_challenge_hash_hex: to_hex(&generator_challenge_hash),
        quadratic_challenge_hash_hex: to_hex(&quadratic_challenge_hash),
    };

    Ok(LinearProverProofGeneration {
        proof_bytes,
        summary,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct ReceiverKeyBetaSigns(pub(super) i64, pub(super) i64);

pub(super) fn receiver_key_tbox_beta_signs(
    seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> ReceiverKeyBetaSigns {
    let sign_byte = generate_linear_proof_aes256ctr_stream(seed, 1, 1)[0];
    let beta3 = if sign_byte & 1 == 0 { 1 } else { -1 };
    let beta4 = if sign_byte & 2 == 0 { 1 } else { -1 };

    ReceiverKeyBetaSigns(beta3, beta4)
}

pub(super) fn receiver_key_z34_message_vector(
    proof_ring: PolynomialRing,
    beta_signs: ReceiverKeyBetaSigns,
) -> CanonicalResult<PolynomialVector> {
    let mut entries =
        vec![vec![0_u64; proof_ring.degree()]; RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS];
    entries[8][0] = positive_mod_i128(i128::from(beta_signs.0), proof_ring.modulus())?;
    entries[8][proof_ring.degree() / 2] =
        positive_mod_i128(i128::from(beta_signs.1), proof_ring.modulus())?;

    PolynomialVector::new(proof_ring, entries)
}

pub(super) fn receiver_key_zero_message_vector(
    proof_ring: PolynomialRing,
    length: usize,
) -> CanonicalResult<PolynomialVector> {
    PolynomialVector::new(proof_ring, vec![vec![0_u64; proof_ring.degree()]; length])
}

pub(super) fn receiver_key_target_commitment_prefix(
    message_key_matrix: &PolynomialMatrix,
    opening_randomness_prefix: &PolynomialVector,
    z34_message_vector: &PolynomialVector,
) -> CanonicalResult<Vec<Vec<u64>>> {
    receiver_key_target_commitment_rows(
        message_key_matrix,
        opening_randomness_prefix,
        0,
        z34_message_vector,
    )
}

pub(super) fn receiver_key_target_commitment_rows(
    message_key_matrix: &PolynomialMatrix,
    opening_randomness_prefix: &PolynomialVector,
    row_start: usize,
    message_vector: &PolynomialVector,
) -> CanonicalResult<Vec<Vec<u64>>> {
    if message_key_matrix.ring() != opening_randomness_prefix.ring()
        || message_key_matrix.ring() != message_vector.ring()
    {
        return Err(invalid_prover(
            "receiver-key target commitment inputs use inconsistent proof rings",
        ));
    }
    if message_key_matrix.columns() != opening_randomness_prefix.len() {
        return Err(invalid_prover(
            "receiver-key message key width does not match opening randomness",
        ));
    }
    if row_start
        .checked_add(message_vector.len())
        .ok_or_else(|| invalid_prover("receiver-key target row range overflowed"))?
        > message_key_matrix.rows()
    {
        return Err(invalid_prover(
            "receiver-key target row range exceeds the message key height",
        ));
    }

    let proof_ring = message_key_matrix.ring();
    let mut entries = Vec::with_capacity(message_vector.len());
    for message_row_index in 0..message_vector.len() {
        let matrix_row_index = row_start + message_row_index;
        let mut row_product = vec![0_u64; proof_ring.degree()];
        for column_index in 0..message_key_matrix.columns() {
            let product = proof_ring.mul_negacyclic(
                message_key_matrix.entry(matrix_row_index, column_index)?,
                &opening_randomness_prefix.entries()[column_index],
            )?;
            row_product = proof_ring.add(&row_product, &product)?;
        }
        entries.push(proof_ring.add(&row_product, &message_vector.entries()[message_row_index])?);
    }

    Ok(entries)
}

pub(super) fn compute_receiver_key_tbox_z3_response(
    proof_ring: PolynomialRing,
    short_witness: &PolynomialVector,
    beta3: i64,
    challenge_seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> CanonicalResult<Vec<Vec<i64>>> {
    let flattened_witness = flatten_nonzero_canonical_vector_to_centered_i64(
        proof_ring,
        short_witness,
        "short witness",
    )?;
    let mut flattened_response = vec![0_i64; 256];
    for (row_index, response_coefficient) in flattened_response.iter_mut().enumerate() {
        let row_sum = sparse_ternary_row_dot_product(
            flattened_witness.length,
            &flattened_witness.nonzero_entries,
            challenge_seed,
            row_index as u64,
            "receiver-key z3 response",
        )?;
        let signed_response = row_sum
            .checked_mul(i128::from(beta3))
            .ok_or_else(|| invalid_prover("receiver-key z3 beta multiplication overflowed"))?;
        *response_coefficient = i64::try_from(signed_response)
            .map_err(|_| invalid_prover("receiver-key z3 response does not fit in i64"))?;
    }

    Ok(split_flattened_signed_polynomials(
        flattened_response,
        proof_ring.degree(),
    ))
}

pub(super) fn compute_receiver_key_tbox_z4_response(
    proof_ring: PolynomialRing,
    tbox_z4_secret: &PolynomialVector,
    beta4: i64,
    challenge_seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> CanonicalResult<Vec<Vec<i64>>> {
    let flattened_secret =
        flatten_nonzero_canonical_vector_to_centered_i64(proof_ring, tbox_z4_secret, "z4 secret")?;
    let mut flattened_response = vec![0_i64; 256];
    for (row_index, response_coefficient) in flattened_response.iter_mut().enumerate() {
        let row_sum = sparse_ternary_row_dot_product(
            flattened_secret.length,
            &flattened_secret.nonzero_entries,
            challenge_seed,
            u64::try_from(256 + row_index)
                .map_err(|_| invalid_prover("receiver-key z4 row domain overflowed"))?,
            "receiver-key z4 response",
        )?;
        let signed_response = row_sum
            .checked_mul(i128::from(beta4))
            .ok_or_else(|| invalid_prover("receiver-key z4 beta multiplication overflowed"))?;
        *response_coefficient = i64::try_from(signed_response)
            .map_err(|_| invalid_prover("receiver-key z4 response does not fit in i64"))?;
    }

    Ok(split_flattened_signed_polynomials(
        flattened_response,
        proof_ring.degree(),
    ))
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(super) struct FlattenedNonzeroCenteredVector {
    length: usize,
    nonzero_entries: Vec<FlattenedNonzeroCenteredCoefficient>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(super) struct FlattenedNonzeroCenteredCoefficient {
    position: usize,
    coefficient: i64,
}

pub(super) fn flatten_nonzero_canonical_vector_to_centered_i64(
    proof_ring: PolynomialRing,
    vector: &PolynomialVector,
    label: &str,
) -> CanonicalResult<FlattenedNonzeroCenteredVector> {
    if vector.ring() != proof_ring {
        return Err(invalid_prover(format!(
            "flattened {label} ring does not match the proof ring"
        )));
    }
    let length = vector
        .len()
        .checked_mul(proof_ring.degree())
        .ok_or_else(|| invalid_prover(format!("flattened {label} length overflowed")))?;
    let mut nonzero_entries = Vec::new();
    for (polynomial_index, polynomial) in vector.entries().iter().enumerate() {
        if polynomial.len() != proof_ring.degree() {
            return Err(invalid_prover(format!(
                "flattened {label} polynomial degree does not match the proof ring"
            )));
        }
        for (coefficient_index, coefficient) in polynomial.iter().enumerate() {
            let centered_coefficient =
                canonical_coefficient_to_centered_i64(proof_ring, *coefficient)?;
            if centered_coefficient == 0 {
                continue;
            }
            let position = polynomial_index
                .checked_mul(proof_ring.degree())
                .and_then(|offset| offset.checked_add(coefficient_index))
                .ok_or_else(|| invalid_prover(format!("flattened {label} index overflowed")))?;
            nonzero_entries.push(FlattenedNonzeroCenteredCoefficient {
                position,
                coefficient: centered_coefficient,
            });
        }
    }

    Ok(FlattenedNonzeroCenteredVector {
        length,
        nonzero_entries,
    })
}

pub(super) fn sparse_ternary_row_dot_product(
    row_length: usize,
    nonzero_entries: &[FlattenedNonzeroCenteredCoefficient],
    seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    domain_separator: u64,
    label: &str,
) -> CanonicalResult<i128> {
    if row_length == 0 {
        return Err(invalid_prover(format!(
            "{label} ternary row length must be non-zero"
        )));
    }
    if nonzero_entries.is_empty() {
        return Ok(0);
    }
    let output_length = row_length
        .checked_mul(2)
        .ok_or_else(|| invalid_prover(format!("{label} ternary row bit length overflowed")))?
        .div_ceil(8);
    let random_bytes =
        generate_linear_proof_aes256ctr_stream(seed, domain_separator, output_length);
    let mut row_sum = 0_i128;
    for entry in nonzero_entries {
        if entry.position >= row_length {
            return Err(invalid_prover(format!(
                "{label} nonzero coefficient position is outside the ternary row"
            )));
        }
        let negative_bit_index = row_length
            .checked_add(entry.position)
            .ok_or_else(|| invalid_prover(format!("{label} negative bit index overflowed")))?;
        let positive_bit = read_bit(&random_bytes, entry.position)?;
        let negative_bit = read_bit(&random_bytes, negative_bit_index)?;
        let sign = i16::from(positive_bit) - i16::from(negative_bit);
        row_sum = row_sum
            .checked_add(i128::from(sign) * i128::from(entry.coefficient))
            .ok_or_else(|| invalid_prover(format!("{label} overflowed")))?;
    }

    Ok(row_sum)
}

pub(super) fn build_receiver_key_tbox_witness_vector(
    proof_ring: PolynomialRing,
    short_witness: &PolynomialVector,
    z34_message_vector: &PolynomialVector,
    hash_mask_blinding_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let tbox_message_vector = receiver_key_quadratic_message_vector(
        proof_ring,
        z34_message_vector,
        hash_mask_blinding_vector,
    )?;
    build_paired_quadratic_witness_vector(
        proof_ring,
        short_witness.entries(),
        tbox_message_vector.entries(),
    )
}
