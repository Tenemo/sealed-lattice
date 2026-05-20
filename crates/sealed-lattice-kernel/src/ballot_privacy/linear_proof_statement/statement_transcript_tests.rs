use super::*;
#[cfg(test)]
mod tests {
    use super::{
        LINEAR_PROOF_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS,
        LinearProofTargetCoefficientRepresentation, derive_linear_statement_transcript,
        derive_transformed_target_vector, source_modulus_inverse_mod_proof_modulus,
        source_polynomial_split_factor,
    };
    use crate::{
        ballot_privacy::{
            linear_proof_parameters::{
                LinearProofEncoding, LinearProofParameterSet, demo_linear_proof_encoding_contract,
                receiver_key_linear_parameter_contract,
            },
            linear_proof_profile_constants::{
                DEMO_GENERATED_PARAMETER_CONTRACT, RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT,
            },
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

    fn target_coefficient_representation(
        vector_case: &serde_json::Value,
    ) -> LinearProofTargetCoefficientRepresentation {
        serde_json::from_value(vector_case["targetCoefficientRepresentation"].clone())
            .expect("target coefficient representation should deserialize")
    }

    #[test]
    fn derives_demo_statement_transcript_shape() {
        let vector_case = generated_vector_case("valid-small-linear-proof");
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
        let public_randomness = decode_hex(
            vector_case["publicRandomnessHex"]
                .as_str()
                .expect("public randomness should be present"),
        )
        .expect("public randomness should decode");

        let transcript = derive_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            target_coefficient_representation(&vector_case),
            &public_randomness,
        )
        .expect("statement transcript should derive");
        let split_factor = source_polynomial_split_factor(&parameter_set, &proof_encoding)
            .expect("split factor should derive");

        assert_eq!(
            transcript.transformed_statement_matrix_rows,
            parameter_set.statement_rows * split_factor
        );
        assert_eq!(
            transcript.transformed_statement_matrix_columns,
            parameter_set.statement_columns * split_factor
        );
        assert_eq!(
            transcript.transformed_target_vector_length,
            parameter_set.statement_rows * split_factor
        );
        assert_eq!(transcript.encoded_statement_bytes, 236_545);
        assert_eq!(transcript.arithmetic_statement_hash_hex.len(), 64);
        assert_eq!(
            transcript.public_parameters_and_statement_hash_hex.len(),
            64
        );
    }

    #[test]
    fn statement_transcript_binds_matrix_target_and_public_randomness() {
        let valid_case = generated_vector_case("valid-small-linear-proof");
        let mutated_statement_case = generated_vector_case("mutated-statement-matrix");
        let mutated_target_case = generated_vector_case("mutated-target-vector");
        let wrong_randomness_case = generated_vector_case("wrong-public-randomness");

        let derive_digest = |vector_case: &serde_json::Value| {
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
            let public_randomness = decode_hex(
                vector_case["publicRandomnessHex"]
                    .as_str()
                    .expect("public randomness should be present"),
            )
            .expect("public randomness should decode");

            derive_linear_statement_transcript(
                &parameter_set,
                &proof_encoding,
                &statement_matrix_coefficients,
                &target_vector_coefficients,
                target_coefficient_representation(vector_case),
                &public_randomness,
            )
            .expect("statement transcript should derive")
            .public_parameters_and_statement_hash_hex
        };

        let valid_digest = derive_digest(&valid_case);

        assert_ne!(valid_digest, derive_digest(&mutated_statement_case));
        assert_ne!(valid_digest, derive_digest(&mutated_target_case));
        assert_ne!(valid_digest, derive_digest(&wrong_randomness_case));
    }

    #[test]
    fn target_lowering_preserves_canonical_source_representatives() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.ring_degree = 4;
        proof_encoding.coefficient_modulus = 97;
        let parameter_set = LinearProofParameterSet {
            profile_id: "unit-linear-lowering-v1".to_string(),
            source: "unit-test".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 4,
            proof_system_ring_degree: 4,
            coefficient_modulus: 17,
            statement_rows: 1,
            statement_columns: 1,
            witness_l2_bound_squared: 1,
            expected_proof_size_bytes: None,
        };
        let zero_statement_matrix = vec![vec![vec![0_u64; 4]]];
        let transformed_target_vector = derive_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &zero_statement_matrix,
            &[vec![0, 1, 16, 9]],
            LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            &[7_u8; 32],
        )
        .expect("target vector should lower");
        let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(17, 97)
            .expect("source modulus should be invertible");

        assert_eq!(
            transformed_target_vector.entries(),
            &[vec![
                0,
                u64::try_from(source_modulus_inverse).expect("inverse should fit u64"),
                u64::try_from((16 * source_modulus_inverse) % 97)
                    .expect("coefficient should fit u64"),
                u64::try_from((9 * source_modulus_inverse) % 97)
                    .expect("coefficient should fit u64"),
            ]]
        );
    }

    #[test]
    fn target_lowering_can_recover_centered_source_representatives() {
        let mut proof_encoding = demo_linear_proof_encoding_contract();
        proof_encoding.ring_degree = 4;
        proof_encoding.coefficient_modulus = 97;
        let parameter_set = LinearProofParameterSet {
            profile_id: "unit-linear-lowering-v1".to_string(),
            source: "unit-test".to_string(),
            relation: "A*w + t = 0".to_string(),
            ring_degree: 4,
            proof_system_ring_degree: 4,
            coefficient_modulus: 17,
            statement_rows: 1,
            statement_columns: 1,
            witness_l2_bound_squared: 1,
            expected_proof_size_bytes: None,
        };
        let zero_statement_matrix = vec![vec![vec![0_u64; 4]]];
        let transformed_target_vector = derive_transformed_target_vector(
            &parameter_set,
            &proof_encoding,
            &zero_statement_matrix,
            &[vec![0, 1, 16, 9]],
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &[7_u8; 32],
        )
        .expect("target vector should lower");
        let source_modulus_inverse = source_modulus_inverse_mod_proof_modulus(17, 97)
            .expect("source modulus should be invertible");
        let scaled_negative_one =
            97_u64 - u64::try_from(source_modulus_inverse).expect("inverse should fit u64");
        let scaled_negative_eight = (97_i128 - (8 * source_modulus_inverse) % 97) % 97;

        assert_eq!(
            transformed_target_vector.entries(),
            &[vec![
                0,
                u64::try_from(source_modulus_inverse).expect("inverse should fit u64"),
                scaled_negative_one,
                u64::try_from(scaled_negative_eight).expect("coefficient should fit u64"),
            ]]
        );
    }

    #[test]
    fn source_modulus_inverse_is_parameterized_by_the_relation_modulus() {
        let proof_modulus = 36_028_797_018_964_597;
        let demo_source_modulus = DEMO_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus;
        let receiver_key_source_modulus =
            RECEIVER_KEY_GENERATED_PARAMETER_CONTRACT.source_coefficient_modulus;

        let demo_inverse =
            source_modulus_inverse_mod_proof_modulus(demo_source_modulus, proof_modulus)
                .expect("demo source modulus should be invertible");
        let receiver_key_inverse =
            source_modulus_inverse_mod_proof_modulus(receiver_key_source_modulus, proof_modulus)
                .expect("receiver-key source modulus should be invertible");

        assert_eq!(
            demo_inverse,
            LINEAR_PROOF_ORIGINAL_MODULUS_INVERSE_MOD_PROOF_MODULUS
        );
        assert_ne!(demo_inverse, receiver_key_inverse);
        assert_eq!(
            (demo_inverse * i128::from(demo_source_modulus)) % i128::from(proof_modulus),
            1
        );
        assert_eq!(
            (receiver_key_inverse * i128::from(receiver_key_source_modulus))
                % i128::from(proof_modulus),
            1
        );
    }

    #[test]
    fn receiver_key_parameter_contract_lowers_to_the_proof_ring_shape() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = demo_linear_proof_encoding_contract();
        let zero_polynomial = vec![0_u64; parameter_set.ring_degree];
        let mut statement_matrix_coefficients =
            vec![
                vec![zero_polynomial.clone(); parameter_set.statement_columns];
                parameter_set.statement_rows
            ];
        statement_matrix_coefficients[0][0][0] = 1;
        statement_matrix_coefficients[1][4][0] = 1;
        let target_vector_coefficients = vec![zero_polynomial; parameter_set.statement_rows];
        let public_randomness = [7_u8; 32];

        let transcript = derive_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix_coefficients,
            &target_vector_coefficients,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("receiver-key statement should lower into the proof ring");

        assert_eq!(
            source_polynomial_split_factor(&parameter_set, &proof_encoding)
                .expect("receiver-key split factor should derive"),
            4
        );
        assert_eq!(transcript.transformed_statement_matrix_rows, 16);
        assert_eq!(transcript.transformed_statement_matrix_columns, 32);
        assert_eq!(transcript.transformed_target_vector_length, 16);
        assert_eq!(transcript.arithmetic_statement_hash_hex.len(), 64);
    }
}
