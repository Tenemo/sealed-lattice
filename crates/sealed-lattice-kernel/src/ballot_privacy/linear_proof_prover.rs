use crate::{
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::to_hex,
};

use super::{
    abdlop_commitment::encode_lazer_demo_compressed_commitment_vector,
    lazer_demo_many_quadratic::{
        build_lazer_demo_many_quadratic_equations, fold_lazer_many_quadratic_equations,
    },
    lazer_demo_public_parameters::derive_lazer_abdlop_public_parameters,
    lazer_demo_quadratic::LazerDemoQuadraticEquation,
    lazer_demo_rng::{
        generate_lazer_demo_aes256ctr_stream, sample_lazer_demo_autostable_challenge_coefficients,
        sample_lazer_demo_uniform_u64_values,
    },
    lazer_demo_tbox_relations::{
        apply_lazer_tbox_z3_response_relations, apply_lazer_tbox_z4_response_relations,
        build_lazer_tbox_prefix_accumulators,
    },
    linear_proof_parameters::{
        LazerDemoProofEncoding, LinearProofParameterSet, linear_proof_profile_for_encoding,
    },
    linear_proof_statement::{
        LinearProofTargetCoefficientRepresentation, derive_lazer_demo_transformed_statement_matrix,
        derive_lazer_demo_transformed_target_vector, source_polynomial_split_factor,
    },
    linear_proof_transcript::{shake128_32, shake128_64, shake128_96},
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::{LazerDemoLinearProofComponents, encode_lazer_demo_linear_proof_components},
};

const ABDLOP_OPENING_RANDOMNESS_BOUND_MODULUS: u64 = 3;
const ABDLOP_OPENING_RANDOMNESS_BOUND_BIT_LENGTH: usize = 2;
const RECEIVER_KEY_PROVER_RANDOMNESS_BYTES: usize = 32;
const RECEIVER_KEY_TBOX_Z34_MESSAGE_POLYNOMIALS: usize = 9;
const RECEIVER_KEY_TBOX_HASH_MASK_POLYNOMIALS: usize = 2;
const RECEIVER_KEY_QUADRATIC_TARGET_TAIL_POLYNOMIALS: usize = 1;

pub(crate) struct LinearProverWitnessInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LazerDemoProofEncoding,
    pub(crate) statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverWitnessSummary {
    pub(crate) relation_witness_polynomial_count: usize,
    pub(crate) short_witness_polynomial_count: usize,
    pub(crate) witness_l2_squared: u128,
    pub(crate) witness_l2_bound_squared: u128,
    pub(crate) norm_slack: u128,
}

pub(crate) struct LinearProverWitnessPreparation {
    short_witness_vector: PolynomialVector,
    summary: LinearProverWitnessSummary,
}

impl LinearProverWitnessPreparation {
    pub(crate) fn summary(&self) -> &LinearProverWitnessSummary {
        &self.summary
    }

    pub(crate) fn short_witness_polynomial_count(&self) -> usize {
        self.short_witness_vector.entries().len()
    }

    fn short_witness_vector(&self) -> &PolynomialVector {
        &self.short_witness_vector
    }

    #[cfg(test)]
    fn short_witness_vector_entries(&self) -> &[Vec<u64>] {
        self.short_witness_vector.entries()
    }
}

pub(crate) struct LinearProverCommitmentInput<'a> {
    pub(crate) proof_encoding: &'a LazerDemoProofEncoding,
    pub(crate) public_randomness: &'a [u8; 32],
    pub(crate) statement_transcript_hash: &'a [u8; 32],
    pub(crate) witness_preparation: &'a LinearProverWitnessPreparation,
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

pub(crate) struct LinearProverProofInput<'a> {
    pub(crate) parameter_set: &'a LinearProofParameterSet,
    pub(crate) proof_encoding: &'a LazerDemoProofEncoding,
    pub(crate) statement_matrix_coefficients: &'a [Vec<Vec<u64>>],
    pub(crate) target_vector_coefficients: &'a [Vec<u64>],
    pub(crate) target_coefficient_representation: LinearProofTargetCoefficientRepresentation,
    pub(crate) source_witness_coefficients: &'a [Vec<i64>],
    pub(crate) public_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    pub(crate) prover_randomness: &'a [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverProofSummary {
    pub(crate) proof_size_bytes: usize,
    pub(crate) abdlop_commitment_hash_hex: String,
    pub(crate) z34_challenge_hash_hex: String,
    pub(crate) generator_challenge_hash_hex: String,
    pub(crate) quadratic_challenge_hash_hex: String,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverProofGeneration {
    pub(crate) proof_bytes: Vec<u8>,
    pub(crate) summary: LinearProverProofSummary,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct LinearProverCommitmentSummary {
    pub(crate) compressed_commitment_polynomial_count: usize,
    pub(crate) opening_randomness_polynomial_count: usize,
    pub(crate) opening_remainder_polynomial_count: usize,
    pub(crate) prover_randomness_seed_bytes: usize,
    pub(crate) subprotocol_seed_bytes: usize,
    pub(crate) abdlop_commitment_hash_hex: String,
}

pub(crate) struct LinearProverCommitmentPreparation {
    compressed_commitment_vector: PolynomialVector,
    opening_remainder_vector: PolynomialVector,
    opening_randomness_vector: PolynomialVector,
    subprotocol_seed: [u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    summary: LinearProverCommitmentSummary,
}

impl LinearProverCommitmentPreparation {
    pub(crate) fn summary(&self) -> &LinearProverCommitmentSummary {
        &self.summary
    }

    pub(crate) fn compressed_commitment_polynomial_count(&self) -> usize {
        self.compressed_commitment_vector.len()
    }

    fn compressed_commitment_vector(&self) -> &PolynomialVector {
        &self.compressed_commitment_vector
    }

    fn opening_remainder_vector(&self) -> &PolynomialVector {
        &self.opening_remainder_vector
    }

    fn opening_randomness_vector(&self) -> &PolynomialVector {
        &self.opening_randomness_vector
    }

    fn subprotocol_seed(&self) -> &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES] {
        &self.subprotocol_seed
    }

    #[cfg(test)]
    fn compressed_commitment_vector_entries(&self) -> &[Vec<u64>] {
        self.compressed_commitment_vector.entries()
    }
}

pub(crate) fn prepare_lazer_linear_prover_witness(
    input: LinearProverWitnessInput<'_>,
) -> CanonicalResult<LinearProverWitnessPreparation> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    validate_source_witness_shape(input.parameter_set, input.source_witness_coefficients)?;
    let source_witness_vector =
        source_witness_to_canonical_vector(input.parameter_set, input.source_witness_coefficients)?;
    let source_statement_matrix =
        source_statement_matrix(input.parameter_set, input.statement_matrix_coefficients)?;
    let source_target_vector =
        source_target_vector(input.parameter_set, input.target_vector_coefficients)?;
    let source_relation_output = source_statement_matrix
        .evaluate_linear_relation(&source_witness_vector, &source_target_vector)?;
    if !is_zero_polynomial_vector(&source_relation_output) {
        return Err(invalid_prover(
            "linear prover source witness does not satisfy A*w + t = 0",
        ));
    }

    let witness_l2_squared = source_witness_l2_squared(input.source_witness_coefficients)?;
    if witness_l2_squared > input.parameter_set.witness_l2_bound_squared {
        return Err(invalid_prover(
            "linear prover source witness exceeds the l2 bound",
        ));
    }

    let transformed_relation_witness = transform_source_witness_to_proof_ring(
        input.parameter_set,
        input.proof_encoding,
        input.source_witness_coefficients,
    )?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let transformed_witness_vector =
        PolynomialVector::new(proof_ring, transformed_relation_witness.clone())?;
    let transformed_statement_matrix = derive_lazer_demo_transformed_statement_matrix(
        input.parameter_set,
        input.proof_encoding,
        input.statement_matrix_coefficients,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let transformed_target_vector = derive_lazer_demo_transformed_target_vector(
        input.parameter_set,
        input.proof_encoding,
        input.statement_matrix_coefficients,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let transformed_relation_output = transformed_statement_matrix
        .evaluate_linear_relation(&transformed_witness_vector, &transformed_target_vector)?;
    if !is_zero_polynomial_vector(&transformed_relation_output) {
        return Err(invalid_prover(
            "linear prover transformed witness does not satisfy the proof-ring relation",
        ));
    }

    let relation_witness_polynomial_count = transformed_relation_witness.len();
    let expected_short_witness_polynomial_count = relation_witness_polynomial_count
        .checked_add(1)
        .ok_or_else(|| invalid_prover("linear prover short witness length overflowed"))?;
    if input.proof_encoding.short_response_vector_length != expected_short_witness_polynomial_count
    {
        return Err(invalid_prover(
            "linear prover witness layout does not match the proof encoding",
        ));
    }

    let norm_slack = input
        .parameter_set
        .witness_l2_bound_squared
        .checked_sub(witness_l2_squared)
        .ok_or_else(|| invalid_prover("linear prover norm slack underflowed"))?;
    let mut short_witness_entries = transformed_relation_witness;
    short_witness_entries.push(binary_expansion_polynomial(proof_ring, norm_slack)?);
    let short_witness_vector = PolynomialVector::new(proof_ring, short_witness_entries)?;
    let summary = LinearProverWitnessSummary {
        relation_witness_polynomial_count,
        short_witness_polynomial_count: expected_short_witness_polynomial_count,
        witness_l2_squared,
        witness_l2_bound_squared: input.parameter_set.witness_l2_bound_squared,
        norm_slack,
    };

    Ok(LinearProverWitnessPreparation {
        short_witness_vector,
        summary,
    })
}

pub(crate) fn prepare_lazer_linear_prover_commitment(
    input: LinearProverCommitmentInput<'_>,
) -> CanonicalResult<LinearProverCommitmentPreparation> {
    input.proof_encoding.validate()?;
    if input.witness_preparation.short_witness_vector().len()
        != input.proof_encoding.short_response_vector_length
    {
        return Err(invalid_prover(
            "linear prover short witness length does not match the proof encoding",
        ));
    }
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let expanded_randomness = shake128_64(&[input.prover_randomness]);
    let mut commitment_randomness_seed = [0_u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES];
    commitment_randomness_seed
        .copy_from_slice(&expanded_randomness[..RECEIVER_KEY_PROVER_RANDOMNESS_BYTES]);
    let mut subprotocol_seed = [0_u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES];
    subprotocol_seed.copy_from_slice(&expanded_randomness[RECEIVER_KEY_PROVER_RANDOMNESS_BYTES..]);

    let opening_randomness_vector = sample_abdlop_opening_randomness_vector(
        proof_ring,
        input.proof_encoding,
        &commitment_randomness_seed,
    )?;
    let public_parameters =
        derive_lazer_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
    let opening_randomness_prefix = PolynomialVector::new(
        proof_ring,
        opening_randomness_vector.entries()
            [..input.proof_encoding.randomness_response_vector_length]
            .to_vec(),
    )?;
    let opening_randomness_suffix = PolynomialVector::new(
        proof_ring,
        opening_randomness_vector.entries()
            [input.proof_encoding.randomness_response_vector_length..]
            .to_vec(),
    )?;
    let short_commitment_product = public_parameters
        .commitment_key_matrix
        .multiply_vector(input.witness_preparation.short_witness_vector())?;
    let opening_product = public_parameters
        .opening_key_matrix
        .multiply_vector(&opening_randomness_prefix)?;
    let uncompressed_commitment = short_commitment_product
        .add(&opening_product)?
        .add(&opening_randomness_suffix)?;
    let (compressed_commitment_vector, opening_remainder_vector) =
        power2round_abdlop_commitment(&uncompressed_commitment, input.proof_encoding)?;
    let encoded_commitment = encode_lazer_demo_compressed_commitment_vector(
        compressed_commitment_vector.entries(),
        input.proof_encoding,
    )?;
    let abdlop_commitment_hash =
        shake128_32(&[input.statement_transcript_hash, &encoded_commitment]);
    let summary = LinearProverCommitmentSummary {
        compressed_commitment_polynomial_count: compressed_commitment_vector.len(),
        opening_randomness_polynomial_count: opening_randomness_vector.len(),
        opening_remainder_polynomial_count: opening_remainder_vector.len(),
        prover_randomness_seed_bytes: RECEIVER_KEY_PROVER_RANDOMNESS_BYTES,
        subprotocol_seed_bytes: subprotocol_seed.len(),
        abdlop_commitment_hash_hex: to_hex(&abdlop_commitment_hash),
    };

    Ok(LinearProverCommitmentPreparation {
        compressed_commitment_vector,
        opening_remainder_vector,
        opening_randomness_vector,
        subprotocol_seed,
        summary,
    })
}

pub(crate) fn generate_lazer_receiver_key_linear_proof(
    input: LinearProverProofInput<'_>,
) -> CanonicalResult<LinearProverProofGeneration> {
    input.parameter_set.validate()?;
    input.proof_encoding.validate()?;
    let proof_profile = linear_proof_profile_for_encoding(input.proof_encoding)?;
    let proof_ring = PolynomialRing::new(
        input.proof_encoding.ring_degree,
        input.proof_encoding.coefficient_modulus,
    )?;
    let statement_transcript =
        super::linear_proof_statement::derive_lazer_demo_linear_statement_transcript(
            input.parameter_set,
            input.proof_encoding,
            input.statement_matrix_coefficients,
            input.target_vector_coefficients,
            input.target_coefficient_representation,
            input.public_randomness,
        )?;
    let witness_preparation = prepare_lazer_linear_prover_witness(LinearProverWitnessInput {
        parameter_set: input.parameter_set,
        proof_encoding: input.proof_encoding,
        statement_matrix_coefficients: input.statement_matrix_coefficients,
        target_vector_coefficients: input.target_vector_coefficients,
        target_coefficient_representation: input.target_coefficient_representation,
        source_witness_coefficients: input.source_witness_coefficients,
        public_randomness: input.public_randomness,
    })?;
    let commitment_preparation =
        prepare_lazer_linear_prover_commitment(LinearProverCommitmentInput {
            proof_encoding: input.proof_encoding,
            public_randomness: input.public_randomness,
            statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
            witness_preparation: &witness_preparation,
            prover_randomness: input.prover_randomness,
        })?;
    let encoded_commitment = encode_lazer_demo_compressed_commitment_vector(
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
        derive_lazer_abdlop_public_parameters(input.public_randomness, input.proof_encoding)?;
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
    let transformed_statement_matrix = derive_lazer_demo_transformed_statement_matrix(
        input.parameter_set,
        input.proof_encoding,
        input.statement_matrix_coefficients,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let transformed_target_vector = derive_lazer_demo_transformed_target_vector(
        input.parameter_set,
        input.proof_encoding,
        input.statement_matrix_coefficients,
        input.target_vector_coefficients,
        input.target_coefficient_representation,
        input.public_randomness,
    )?;
    let transformed_relation_witness = PolynomialVector::new(
        proof_ring,
        short_witness.entries()[..short_witness.len() - 1].to_vec(),
    )?;
    let tbox_z4_secret = transformed_statement_matrix
        .evaluate_linear_relation(&transformed_relation_witness, &transformed_target_vector)?;
    let euclidean_response_vector = compute_receiver_key_tbox_z3_response(
        proof_ring,
        short_witness,
        beta_signs.0,
        &z34_challenge_hash,
    )?;
    let infinity_response_vector = compute_receiver_key_tbox_z4_response(
        proof_ring,
        &tbox_z4_secret,
        beta_signs.1,
        &z34_challenge_hash,
    )?;

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
        build_lazer_tbox_prefix_accumulators(&generator_challenge_hash, input.proof_encoding)?;
    apply_lazer_tbox_z4_response_relations(
        &mut tbox_accumulators,
        &transformed_statement_matrix,
        &transformed_target_vector,
        &infinity_response_vector,
        &z34_challenge_hash,
        input.proof_encoding,
    )?;
    apply_lazer_tbox_z3_response_relations(
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
        build_lazer_demo_many_quadratic_equations(&tbox_accumulators, &hash_mask_vector)?;
    let many_quadratic_fold = fold_lazer_many_quadratic_equations(
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
    let folded_relation_value = evaluate_lazer_quadratic_equation(
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
    let centered_challenge_polynomial = sample_lazer_demo_autostable_challenge_coefficients(
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

    let proof_bytes = encode_lazer_demo_linear_proof_components(
        LazerDemoLinearProofComponents {
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
struct ReceiverKeyBetaSigns(i64, i64);

fn receiver_key_tbox_beta_signs(
    seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> ReceiverKeyBetaSigns {
    let sign_byte = generate_lazer_demo_aes256ctr_stream(seed, 1, 1)[0];
    let beta3 = if sign_byte & 1 == 0 { 1 } else { -1 };
    let beta4 = if sign_byte & 2 == 0 { 1 } else { -1 };

    ReceiverKeyBetaSigns(beta3, beta4)
}

fn receiver_key_z34_message_vector(
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

fn receiver_key_zero_message_vector(
    proof_ring: PolynomialRing,
    length: usize,
) -> CanonicalResult<PolynomialVector> {
    PolynomialVector::new(proof_ring, vec![vec![0_u64; proof_ring.degree()]; length])
}

fn receiver_key_target_commitment_prefix(
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

fn receiver_key_target_commitment_rows(
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

fn compute_receiver_key_tbox_z3_response(
    proof_ring: PolynomialRing,
    short_witness: &PolynomialVector,
    beta3: i64,
    challenge_seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> CanonicalResult<Vec<Vec<i64>>> {
    let flattened_witness = flatten_canonical_vector_to_centered_i64(proof_ring, short_witness)?;
    let mut flattened_response = vec![0_i64; 256];
    for (row_index, response_coefficient) in flattened_response.iter_mut().enumerate() {
        let row = sample_lazer_demo_ternary_row(
            flattened_witness.len(),
            challenge_seed,
            row_index as u64,
        )?;
        let mut row_sum = 0_i128;
        for (sign, witness_coefficient) in row.iter().zip(&flattened_witness) {
            row_sum = row_sum
                .checked_add(i128::from(*sign) * i128::from(*witness_coefficient))
                .ok_or_else(|| invalid_prover("receiver-key z3 response overflowed"))?;
        }
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

fn compute_receiver_key_tbox_z4_response(
    proof_ring: PolynomialRing,
    tbox_z4_secret: &PolynomialVector,
    beta4: i64,
    challenge_seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
) -> CanonicalResult<Vec<Vec<i64>>> {
    let flattened_secret = flatten_canonical_vector_to_centered_i64(proof_ring, tbox_z4_secret)?;
    let mut flattened_response = vec![0_i64; 256];
    for (row_index, response_coefficient) in flattened_response.iter_mut().enumerate() {
        let row = sample_lazer_demo_ternary_row(
            flattened_secret.len(),
            challenge_seed,
            u64::try_from(256 + row_index)
                .map_err(|_| invalid_prover("receiver-key z4 row domain overflowed"))?,
        )?;
        let mut row_sum = 0_i128;
        for (sign, secret_coefficient) in row.iter().zip(&flattened_secret) {
            row_sum = row_sum
                .checked_add(i128::from(*sign) * i128::from(*secret_coefficient))
                .ok_or_else(|| invalid_prover("receiver-key z4 response overflowed"))?;
        }
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

fn sample_lazer_demo_ternary_row(
    row_length: usize,
    seed: &[u8; RECEIVER_KEY_PROVER_RANDOMNESS_BYTES],
    domain_separator: u64,
) -> CanonicalResult<Vec<i8>> {
    let output_length = row_length
        .checked_mul(2)
        .ok_or_else(|| invalid_prover("ternary row bit length overflowed"))?
        .div_ceil(8);
    let random_bytes = generate_lazer_demo_aes256ctr_stream(seed, domain_separator, output_length);
    let mut row = vec![0_i8; row_length];
    for (row_index, row_value) in row.iter_mut().enumerate() {
        let positive_bit = read_bit(&random_bytes, row_index)?;
        let negative_bit = read_bit(&random_bytes, row_length + row_index)?;
        *row_value = i8::try_from(i16::from(positive_bit) - i16::from(negative_bit))
            .map_err(|_| invalid_prover("ternary row sample does not fit in i8"))?;
    }

    Ok(row)
}

fn build_receiver_key_tbox_witness_vector(
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

fn receiver_key_quadratic_message_vector(
    proof_ring: PolynomialRing,
    z34_message_vector: &PolynomialVector,
    hash_mask_blinding_vector: &PolynomialVector,
) -> CanonicalResult<PolynomialVector> {
    let mut entries = z34_message_vector.entries().to_vec();
    entries.extend_from_slice(hash_mask_blinding_vector.entries());

    PolynomialVector::new(proof_ring, entries)
}

fn build_paired_quadratic_witness_vector(
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

fn receiver_key_hash_mask_from_tbox_equations(
    proof_ring: PolynomialRing,
    folded_tbox_equations: &[LazerDemoQuadraticEquation],
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
        let evaluated_polynomial = evaluate_lazer_quadratic_equation_with_available_witnesses(
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
        let evaluated_polynomial = evaluate_lazer_quadratic_equation_with_available_witnesses(
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

fn evaluate_lazer_quadratic_equation_with_available_witnesses(
    equation: &LazerDemoQuadraticEquation,
    full_tbox_witness: &PolynomialVector,
    z34_tbox_witness: &PolynomialVector,
) -> CanonicalResult<Vec<u64>> {
    if equation.dimension() == full_tbox_witness.len() {
        evaluate_lazer_quadratic_equation(equation, full_tbox_witness)
    } else if equation.dimension() == z34_tbox_witness.len() {
        evaluate_lazer_quadratic_equation(equation, z34_tbox_witness)
    } else {
        Err(invalid_prover(format!(
            "quadratic equation witness shape does not match the available receiver-key tbox witnesses: full {}, z34 {}, relation {}",
            full_tbox_witness.len(),
            z34_tbox_witness.len(),
            equation.dimension()
        )))
    }
}

fn evaluate_lazer_quadratic_equation(
    equation: &LazerDemoQuadraticEquation,
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
    evaluated_polynomial = proof_ring.add(&evaluated_polynomial, &linear_product)?;
    let quadratic_matrix_product = equation.quadratic_terms().multiply_vector(witness)?;
    let quadratic_product = dot_polynomial_vectors(proof_ring, witness, &quadratic_matrix_product)?;

    proof_ring.add(&evaluated_polynomial, &quadratic_product)
}

fn dot_sparse_vector_with_dense_vector(
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
        let product = proof_ring.mul_negacyclic(
            entry.coefficients(),
            &dense_vector.entries()[entry.position()],
        )?;
        output = proof_ring.add(&output, &product)?;
    }

    Ok(output)
}

fn dot_polynomial_vectors(
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
        let product = proof_ring.mul_negacyclic(left_polynomial, right_polynomial)?;
        output = proof_ring.add(&output, &product)?;
    }

    Ok(output)
}

fn multiply_polynomial_by_vector(
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

fn signed_polynomial_to_canonical(
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

fn flatten_canonical_vector_to_centered_i64(
    proof_ring: PolynomialRing,
    vector: &PolynomialVector,
) -> CanonicalResult<Vec<i64>> {
    if vector.ring() != proof_ring {
        return Err(invalid_prover(
            "flattened vector ring does not match the proof ring",
        ));
    }
    vector
        .entries()
        .iter()
        .flat_map(|polynomial| polynomial.iter())
        .map(|coefficient| canonical_coefficient_to_centered_i64(proof_ring, *coefficient))
        .collect()
}

fn canonical_vector_to_centered_entries(
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

fn canonical_coefficient_to_centered_i64(
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

fn split_flattened_signed_polynomials(
    flattened_coefficients: Vec<i64>,
    ring_degree: usize,
) -> Vec<Vec<i64>> {
    flattened_coefficients
        .chunks_exact(ring_degree)
        .map(<[i64]>::to_vec)
        .collect()
}

fn make_zero_high_bits_hint(
    proof_ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
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

fn validate_zero_high_bits_low_part(
    proof_ring: PolynomialRing,
    recovery_input: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
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

fn gamma_decompression_high_bits(
    coefficient: u64,
    proof_encoding: &LazerDemoProofEncoding,
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

fn encode_quadratic_challenge_input_for_hash(
    proof_ring: PolynomialRing,
    target_tail_polynomials: &[Vec<u64>],
    verifier_polynomial: &[u64],
    recovered_high_bits: &[Vec<u64>],
    proof_encoding: &LazerDemoProofEncoding,
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

fn encode_uniform_polynomial_vector_for_hash(
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

fn encode_uniform_polynomial_for_hash(
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

struct ProverBitWriter {
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

fn read_bit(bytes: &[u8], bit_index: usize) -> CanonicalResult<u8> {
    let byte_index = bit_index / 8;
    if byte_index >= bytes.len() {
        return Err(invalid_prover("bit stream ended early"));
    }
    Ok((bytes[byte_index] >> (bit_index % 8)) & 1)
}

fn validate_source_witness_shape(
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

fn source_statement_matrix(
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

fn source_target_vector(
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

fn source_witness_to_canonical_vector(
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

fn source_witness_l2_squared(source_witness_coefficients: &[Vec<i64>]) -> CanonicalResult<u128> {
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

fn transform_source_witness_to_proof_ring(
    parameter_set: &LinearProofParameterSet,
    proof_encoding: &LazerDemoProofEncoding,
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

fn split_signed_polynomial_into_proof_ring(
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

fn binary_expansion_polynomial(
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

fn sample_abdlop_opening_randomness_vector(
    proof_ring: PolynomialRing,
    proof_encoding: &LazerDemoProofEncoding,
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
        let sampled_coefficients = sample_lazer_demo_uniform_u64_values(
            proof_ring.degree(),
            ABDLOP_OPENING_RANDOMNESS_BOUND_MODULUS,
            ABDLOP_OPENING_RANDOMNESS_BOUND_BIT_LENGTH,
            seed,
            domain_separator,
        )?;
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

fn power2round_abdlop_commitment(
    uncompressed_commitment: &PolynomialVector,
    proof_encoding: &LazerDemoProofEncoding,
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

fn is_zero_polynomial_vector(vector: &PolynomialVector) -> bool {
    vector
        .entries()
        .iter()
        .all(|polynomial| polynomial.iter().all(|coefficient| *coefficient == 0))
}

fn is_zero_polynomial(polynomial: &[u64]) -> bool {
    polynomial.iter().all(|coefficient| *coefficient == 0)
}

fn positive_mod_i128(value: i128, modulus: u64) -> CanonicalResult<u64> {
    if modulus <= 1 {
        return Err(invalid_prover(
            "linear prover modulus must be greater than one",
        ));
    }
    let modulus = i128::from(modulus);
    let mut reduced = value % modulus;
    if reduced < 0 {
        reduced += modulus;
    }

    u64::try_from(reduced)
        .map_err(|_| invalid_prover("linear prover reduced coefficient does not fit in u64"))
}

fn invalid_prover(message: impl Into<String>) -> CanonicalError {
    CanonicalError::new(CanonicalErrorCode::InvalidFixture, message)
}

#[cfg(test)]
mod tests {
    use super::{
        LinearProverCommitmentInput, LinearProverProofInput, LinearProverWitnessInput,
        generate_lazer_receiver_key_linear_proof, prepare_lazer_linear_prover_commitment,
        prepare_lazer_linear_prover_witness,
    };
    use crate::{
        ballot_privacy::{
            linear_proof_parameters::{
                receiver_key_linear_parameter_contract, receiver_key_linear_proof_encoding_contract,
            },
            linear_proof_statement::{
                LinearProofTargetCoefficientRepresentation,
                derive_lazer_demo_linear_statement_transcript,
            },
            linear_proof_verifier::verify_linear_proof_vector_case_value,
            polynomial_ring::PolynomialRing,
        },
        hashing::to_hex,
    };
    use serde_json::json;

    type ReceiverKeyFixture = (Vec<Vec<Vec<u64>>>, Vec<Vec<u64>>, Vec<Vec<i64>>);

    fn zero_source_polynomial() -> Vec<u64> {
        vec![0_u64; 256]
    }

    fn zero_witness_polynomial() -> Vec<i64> {
        vec![0_i64; 256]
    }

    fn unit_polynomial() -> Vec<u64> {
        let mut polynomial = zero_source_polynomial();
        polynomial[0] = 1;
        polynomial
    }

    fn canonical_signed_polynomial(polynomial: &[i64], modulus: u64) -> Vec<u64> {
        polynomial
            .iter()
            .map(|coefficient| {
                if *coefficient < 0 {
                    modulus - coefficient.unsigned_abs()
                } else {
                    coefficient.unsigned_abs()
                }
            })
            .collect()
    }

    fn receiver_key_fixture() -> ReceiverKeyFixture {
        let parameter_set = receiver_key_linear_parameter_contract();
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate");
        let mut witness = vec![zero_witness_polynomial(); parameter_set.statement_columns];
        witness[0][0] = 2;
        witness[0][5] = -1;
        witness[1][1] = 1;
        witness[4][0] = -2;
        witness[5][7] = 1;

        let mut statement_matrix =
            vec![
                vec![zero_source_polynomial(); parameter_set.statement_columns];
                parameter_set.statement_rows
            ];
        for (row_index, statement_matrix_row) in statement_matrix
            .iter_mut()
            .enumerate()
            .take(parameter_set.statement_rows)
        {
            statement_matrix_row[row_index] = unit_polynomial();
            statement_matrix_row[row_index + 4] = unit_polynomial();
        }

        let target_vector = (0..parameter_set.statement_rows)
            .map(|row_index| {
                let secret_polynomial = canonical_signed_polynomial(
                    &witness[row_index],
                    parameter_set.coefficient_modulus,
                );
                let error_polynomial = canonical_signed_polynomial(
                    &witness[row_index + 4],
                    parameter_set.coefficient_modulus,
                );
                let public_key_polynomial = source_ring
                    .add(&secret_polynomial, &error_polynomial)
                    .expect("public key polynomial should add");
                source_ring
                    .neg(&public_key_polynomial)
                    .expect("target polynomial should negate")
            })
            .collect::<Vec<_>>();

        (statement_matrix, target_vector, witness)
    }

    #[test]
    fn prepares_receiver_key_short_witness_with_norm_slack_coordinate() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, target_vector, witness) = receiver_key_fixture();

        let preparation = prepare_lazer_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &[0_u8; 32],
        })
        .expect("receiver-key witness should prepare");

        let summary = preparation.summary();
        assert_eq!(summary.relation_witness_polynomial_count, 32);
        assert_eq!(summary.short_witness_polynomial_count, 33);
        assert_eq!(summary.witness_l2_squared, 11);
        assert_eq!(summary.witness_l2_bound_squared, 8_192);
        assert_eq!(summary.norm_slack, 8_181);
        assert_eq!(
            preparation.short_witness_vector_entries().len(),
            proof_encoding.short_response_vector_length
        );
        let norm_slack_polynomial = preparation
            .short_witness_vector_entries()
            .last()
            .expect("norm slack polynomial should exist");
        for (bit_index, coefficient) in norm_slack_polynomial.iter().enumerate() {
            assert_eq!(
                *coefficient,
                u64::from(((summary.norm_slack >> bit_index) & 1) != 0)
            );
        }
        assert_eq!(
            preparation.short_witness_vector_entries()[0][0],
            2,
            "first split polynomial should keep the source witness coefficient"
        );
        assert_eq!(
            preparation.short_witness_vector_entries()[1][1],
            proof_encoding.coefficient_modulus - 1,
            "negative source witness coefficients must be canonical in the proof ring"
        );
    }

    #[test]
    fn rejects_receiver_key_witness_that_breaks_the_source_relation() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, mut target_vector, witness) = receiver_key_fixture();
        target_vector[0][0] = (target_vector[0][0] + 1) % parameter_set.coefficient_modulus;

        let error = match prepare_lazer_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &[0_u8; 32],
        }) {
            Ok(_) => panic!("changed target should fail source relation checking"),
            Err(error) => error,
        };

        assert!(error.message.contains("source witness"));
    }

    #[test]
    fn rejects_receiver_key_witness_outside_the_exact_norm_bound() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, mut target_vector, mut witness) = receiver_key_fixture();
        witness[0][0] = 100;
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate");
        let mut public_key_polynomial =
            canonical_signed_polynomial(&witness[0], parameter_set.coefficient_modulus);
        public_key_polynomial = source_ring
            .add(
                &public_key_polynomial,
                &canonical_signed_polynomial(&witness[4], parameter_set.coefficient_modulus),
            )
            .expect("public key polynomial should add");
        target_vector[0] = source_ring
            .neg(&public_key_polynomial)
            .expect("target polynomial should negate");

        let error = match prepare_lazer_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &[0_u8; 32],
        }) {
            Ok(_) => panic!("oversized witness should fail the norm bound"),
            Err(error) => error,
        };

        assert!(error.message.contains("l2 bound"));
    }

    #[test]
    fn prepares_receiver_key_abdlop_commitment_from_private_randomness() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, target_vector, witness) = receiver_key_fixture();
        let public_randomness = [0_u8; 32];
        let witness_preparation = prepare_lazer_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
        })
        .expect("receiver-key witness should prepare");
        let statement_transcript = derive_lazer_demo_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix,
            &target_vector,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("statement transcript should derive");

        let commitment = prepare_lazer_linear_prover_commitment(LinearProverCommitmentInput {
            proof_encoding: &proof_encoding,
            public_randomness: &public_randomness,
            statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
            witness_preparation: &witness_preparation,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key commitment should prepare");
        let repeated_commitment =
            prepare_lazer_linear_prover_commitment(LinearProverCommitmentInput {
                proof_encoding: &proof_encoding,
                public_randomness: &public_randomness,
                statement_transcript_hash: &statement_transcript
                    .public_parameters_and_statement_hash,
                witness_preparation: &witness_preparation,
                prover_randomness: &[9_u8; 32],
            })
            .expect("receiver-key commitment should repeat");
        let changed_commitment =
            prepare_lazer_linear_prover_commitment(LinearProverCommitmentInput {
                proof_encoding: &proof_encoding,
                public_randomness: &public_randomness,
                statement_transcript_hash: &statement_transcript
                    .public_parameters_and_statement_hash,
                witness_preparation: &witness_preparation,
                prover_randomness: &[10_u8; 32],
            })
            .expect("changed receiver-key commitment should prepare");

        assert_eq!(
            commitment.summary().compressed_commitment_polynomial_count,
            proof_encoding.compressed_commitment_vector_length
        );
        assert_eq!(commitment.summary().opening_randomness_polynomial_count, 55);
        assert_eq!(
            commitment.summary().opening_remainder_polynomial_count,
            proof_encoding.compressed_commitment_vector_length
        );
        assert_eq!(commitment.summary().prover_randomness_seed_bytes, 32);
        assert_eq!(commitment.summary().subprotocol_seed_bytes, 32);
        assert_eq!(
            commitment.summary().abdlop_commitment_hash_hex,
            repeated_commitment.summary().abdlop_commitment_hash_hex
        );
        assert_ne!(
            commitment.summary().abdlop_commitment_hash_hex,
            changed_commitment.summary().abdlop_commitment_hash_hex
        );
        assert!(
            commitment
                .compressed_commitment_vector_entries()
                .iter()
                .flatten()
                .all(|coefficient| *coefficient
                    < (1_u64 << proof_encoding.compressed_coefficient_bit_length))
        );
    }

    #[test]
    fn generated_receiver_key_proof_bytes_verify_and_bind_public_inputs() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, target_vector, witness) = receiver_key_fixture();
        let public_randomness = [0_u8; 32];
        let first_generation = generate_lazer_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key proof generation should succeed");
        let repeated_generation =
            generate_lazer_receiver_key_linear_proof(LinearProverProofInput {
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                statement_matrix_coefficients: &statement_matrix,
                target_vector_coefficients: &target_vector,
                target_coefficient_representation:
                    LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
                source_witness_coefficients: &witness,
                public_randomness: &public_randomness,
                prover_randomness: &[9_u8; 32],
            })
            .expect("receiver-key proof generation should repeat");
        let changed_generation = generate_lazer_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[10_u8; 32],
        })
        .expect("changed seed proof generation should succeed");

        assert_eq!(
            first_generation.proof_bytes,
            repeated_generation.proof_bytes
        );
        assert_ne!(first_generation.proof_bytes, changed_generation.proof_bytes);
        assert_eq!(
            first_generation.summary.proof_size_bytes,
            first_generation.proof_bytes.len()
        );
        assert_eq!(
            first_generation.summary.abdlop_commitment_hash_hex.len(),
            64
        );
        assert_eq!(
            first_generation.summary.quadratic_challenge_hash_hex.len(),
            64
        );

        let valid_case = json!({
            "caseName": "generated-receiver-key-proof",
            "description": "Receiver-key linear proof generated by the Rust prover.",
            "mutation": "none",
            "expectedOutcome": "accept",
            "upstreamVectorAvailable": true,
            "parameterSet": parameter_set,
            "proofEncoding": proof_encoding,
            "publicRandomnessHex": to_hex(&public_randomness),
            "statementMatrixCoefficients": statement_matrix,
            "targetVectorCoefficients": target_vector,
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "proofHex": to_hex(&first_generation.proof_bytes),
            "expectedProofSizeBytes": first_generation.proof_bytes.len()
        });
        let verification = verify_linear_proof_vector_case_value(&valid_case);
        assert_eq!(
            verification["ok"], true,
            "generated receiver-key proof should verify: {verification}"
        );

        let mut mutated_case = valid_case.clone();
        mutated_case["caseName"] = json!("generated-receiver-key-proof-mutated-target");
        mutated_case["expectedOutcome"] = json!("reject");
        mutated_case["targetVectorCoefficients"][0][0] = json!(
            (mutated_case["targetVectorCoefficients"][0][0]
                .as_u64()
                .expect("target coefficient should be a number")
                + 1)
                % parameter_set.coefficient_modulus
        );
        let mutated_verification = verify_linear_proof_vector_case_value(&mutated_case);
        assert_eq!(
            mutated_verification["ok"], false,
            "mutated receiver-key target should fail: {mutated_verification}"
        );
    }
}
