#[cfg(test)]
mod tests {
    use super::super::{
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
            linear_proof_profile_constants::DEMO_GENERATED_PROFILE,
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
        let gamma = u64::try_from(DEMO_GENERATED_PROFILE.decompression_gamma)
            .expect("demo gamma should fit in u64");
        let half_gamma = gamma / 2;
        assert_eq!(
            gamma_decompression_high_bits(gamma, &proof_encoding, proof_profile)
                .expect("high bits should compute"),
            1
        );
        assert_eq!(
            gamma_decompression_high_bits(gamma + half_gamma, &proof_encoding, proof_profile)
                .expect("half low part should stay positive"),
            1
        );
        assert_eq!(
            gamma_decompression_high_bits(gamma + half_gamma + 1, &proof_encoding, proof_profile)
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

        let mut mismatched_hint_encoding = proof_encoding.clone();
        mismatched_hint_encoding.hint_vector_length += 1;
        let error = validate_quadratic_challenge(
            &generator_challenge_hash,
            &public_randomness,
            &decoded_proof,
            &mismatched_hint_encoding,
            &many_quadratic_fold,
        )
        .expect_err("hint vector length mismatch should fail before decompression");
        assert!(error.message.contains("hint vector length"));

        let mut mismatched_commitment_encoding = proof_encoding.clone();
        mismatched_commitment_encoding.compressed_commitment_vector_length += 1;
        let error = validate_quadratic_challenge(
            &generator_challenge_hash,
            &public_randomness,
            &decoded_proof,
            &mismatched_commitment_encoding,
            &many_quadratic_fold,
        )
        .expect_err("compressed commitment length mismatch should fail before decompression");
        assert!(
            error
                .message
                .contains("compressed commitment vector length")
        );
    }

    fn decode_hash(hash_hex: &str) -> [u8; 32] {
        let bytes = decode_hex(hash_hex).expect("hash should decode");
        bytes
            .as_slice()
            .try_into()
            .expect("hash should contain exactly 32 bytes")
    }
}
