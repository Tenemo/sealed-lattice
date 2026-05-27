use super::*;

#[cfg(test)]
mod tests {
    use super::{
        LinearProverCommitmentInput, LinearProverProofInput, LinearProverWitnessInput,
        SparseLinearProverProofInput, SparseLinearProverWitnessInput,
        generate_receiver_key_linear_proof, generate_sparse_linear_proof,
        prepare_linear_prover_commitment, prepare_linear_prover_witness,
        prepare_sparse_linear_prover_witness,
    };
    use crate::{
        ballot_privacy::linear_proof::{
            parameters::{
                receiver_key_linear_parameter_contract, receiver_key_linear_proof_encoding_contract,
            },
            profile_constants::RECEIVER_KEY_GENERATED_PROFILE,
            statement::{
                LinearProofMatrixCoefficientRepresentation,
                LinearProofTargetCoefficientRepresentation, derive_linear_statement_transcript,
            },
            verifier::{
                SparseLinearProofVerificationInput, verify_linear_proof_vector_case_value,
                verify_sparse_linear_proof_components,
            },
        },
        ballot_privacy::{
            polynomial_ring::PolynomialRing,
            sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
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
    fn centered_matrix_representation_preserves_negative_source_coefficients() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let source_ring =
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate");
        let (mut statement_matrix, mut target_vector, witness) = receiver_key_fixture();
        statement_matrix[0][0][0] = parameter_set.coefficient_modulus - 1;
        let negated_secret_polynomial = source_ring
            .neg(&canonical_signed_polynomial(
                &witness[0],
                parameter_set.coefficient_modulus,
            ))
            .expect("secret polynomial should negate");
        let error_polynomial =
            canonical_signed_polynomial(&witness[4], parameter_set.coefficient_modulus);
        let relation_without_target = source_ring
            .add(&negated_secret_polynomial, &error_polynomial)
            .expect("row relation should add");
        target_vector[0] = source_ring
            .neg(&relation_without_target)
            .expect("target polynomial should negate");

        prepare_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &[0_u8; 32],
        })
        .expect("centered dense matrix coefficients should preserve the proof-ring relation");

        let public_randomness = [0_u8; 32];
        let dense_generation = generate_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[7_u8; 32],
        })
        .expect("centered dense proof should generate");
        let valid_dense_case = json!({
            "caseName": "centered-matrix-dense-proof",
            "description": "Dense proof with a centered negative matrix coefficient.",
            "mutation": "none",
            "expectedOutcome": "accept",
            "upstreamVectorAvailable": true,
            "parameterSet": parameter_set,
            "proofEncoding": proof_encoding,
            "publicRandomnessHex": to_hex(&public_randomness),
            "statementMatrixCoefficients": statement_matrix,
            "targetVectorCoefficients": target_vector,
            "matrixCoefficientRepresentation": "centeredSignedSourceModulus",
            "targetCoefficientRepresentation": "centeredSignedSourceModulus",
            "proofHex": to_hex(&dense_generation.proof_bytes),
            "expectedProofSizeBytes": dense_generation.proof_bytes.len()
        });
        let dense_verification = verify_linear_proof_vector_case_value(&valid_dense_case);
        assert_eq!(
            dense_verification["ok"], true,
            "centered dense proof should verify: {dense_verification}"
        );
        let mut mutated_dense_case = valid_dense_case.clone();
        mutated_dense_case["caseName"] = json!("canonical-matrix-dense-proof-mutation");
        mutated_dense_case["expectedOutcome"] = json!("reject");
        mutated_dense_case["matrixCoefficientRepresentation"] =
            json!("canonicalUnsignedSourceModulus");
        let mutated_dense_verification = verify_linear_proof_vector_case_value(&mutated_dense_case);
        assert_eq!(
            mutated_dense_verification["ok"], false,
            "changed dense matrix representation should fail proof binding: {mutated_dense_verification}"
        );

        let mut sparse_entries = Vec::new();
        for (row_index, row) in statement_matrix.iter().enumerate() {
            for (column_index, polynomial) in row.iter().enumerate() {
                if polynomial.iter().any(|coefficient| *coefficient != 0) {
                    sparse_entries.push(SparsePolynomialMatrixEntry::new(
                        row_index,
                        column_index,
                        polynomial.clone(),
                    ));
                }
            }
        }
        let sparse_statement_matrix = SparsePolynomialMatrix::new(
            source_ring,
            parameter_set.statement_rows,
            parameter_set.statement_columns,
            sparse_entries,
        )
        .expect("sparse statement matrix should validate");
        prepare_sparse_linear_prover_witness(SparseLinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            source_statement_matrix: &sparse_statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
        })
        .expect("centered sparse matrix coefficients should preserve the proof-ring relation");

        let sparse_generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            source_statement_matrix: &sparse_statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[8_u8; 32],
        })
        .expect("centered sparse proof should generate");
        let sparse_verification =
            verify_sparse_linear_proof_components(SparseLinearProofVerificationInput {
                case_name: "centered-matrix-sparse-proof",
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex: &to_hex(&public_randomness),
                source_statement_matrix: &sparse_statement_matrix,
                target_vector_coefficients: &target_vector,
                matrix_coefficient_representation:
                    LinearProofMatrixCoefficientRepresentation::CenteredSignedSourceModulus,
                target_coefficient_representation:
                    LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
                proof_hex: &to_hex(&sparse_generation.proof_bytes),
                expected_proof_size_bytes: Some(sparse_generation.proof_bytes.len()),
            });
        assert_eq!(
            sparse_verification["ok"], true,
            "centered sparse proof should verify: {sparse_verification}"
        );
        let mutated_sparse_verification =
            verify_sparse_linear_proof_components(SparseLinearProofVerificationInput {
                case_name: "canonical-matrix-sparse-proof-mutation",
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex: &to_hex(&public_randomness),
                source_statement_matrix: &sparse_statement_matrix,
                target_vector_coefficients: &target_vector,
                matrix_coefficient_representation:
                    LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
                target_coefficient_representation:
                    LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
                proof_hex: &to_hex(&sparse_generation.proof_bytes),
                expected_proof_size_bytes: Some(sparse_generation.proof_bytes.len()),
            });
        assert_eq!(
            mutated_sparse_verification["ok"], false,
            "changed sparse matrix representation should fail proof binding: {mutated_sparse_verification}"
        );
    }

    #[test]
    fn prepares_receiver_key_short_witness_with_norm_slack_coordinate() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, target_vector, witness) = receiver_key_fixture();

        let preparation = prepare_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
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
        assert_eq!(
            summary.witness_l2_bound_squared,
            RECEIVER_KEY_GENERATED_PROFILE.exact_norm_bound_squared as u128
        );
        assert_eq!(
            summary.norm_slack,
            RECEIVER_KEY_GENERATED_PROFILE.exact_norm_bound_squared as u128
                - summary.witness_l2_squared
        );
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

        let error = match prepare_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
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

        let error = match prepare_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
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
        let witness_preparation = prepare_linear_prover_witness(LinearProverWitnessInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
        })
        .expect("receiver-key witness should prepare");
        let statement_transcript = derive_linear_statement_transcript(
            &parameter_set,
            &proof_encoding,
            &statement_matrix,
            &target_vector,
            LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            &public_randomness,
        )
        .expect("statement transcript should derive");

        let commitment = prepare_linear_prover_commitment(LinearProverCommitmentInput {
            proof_encoding: &proof_encoding,
            public_randomness: &public_randomness,
            statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
            witness_preparation: &witness_preparation,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key commitment should prepare");
        let repeated_commitment = prepare_linear_prover_commitment(LinearProverCommitmentInput {
            proof_encoding: &proof_encoding,
            public_randomness: &public_randomness,
            statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
            witness_preparation: &witness_preparation,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key commitment should repeat");
        let changed_commitment = prepare_linear_prover_commitment(LinearProverCommitmentInput {
            proof_encoding: &proof_encoding,
            public_randomness: &public_randomness,
            statement_transcript_hash: &statement_transcript.public_parameters_and_statement_hash,
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
        let first_generation = generate_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key proof generation should succeed");
        let repeated_generation = generate_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[9_u8; 32],
        })
        .expect("receiver-key proof generation should repeat");
        let changed_generation = generate_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
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

    #[test]
    fn sparse_generated_proof_bytes_match_dense_compatible_statement() {
        let parameter_set = receiver_key_linear_parameter_contract();
        let proof_encoding = receiver_key_linear_proof_encoding_contract();
        let (statement_matrix, target_vector, witness) = receiver_key_fixture();
        let public_randomness = [0_u8; 32];
        let dense_generation = generate_receiver_key_linear_proof(LinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            statement_matrix_coefficients: &statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[12_u8; 32],
        })
        .expect("dense proof generation should succeed");
        let mut sparse_entries = Vec::new();
        for (row_index, row) in statement_matrix.iter().enumerate() {
            for (column_index, polynomial) in row.iter().enumerate() {
                if polynomial.iter().any(|coefficient| *coefficient != 0) {
                    sparse_entries.push(SparsePolynomialMatrixEntry::new(
                        row_index,
                        column_index,
                        polynomial.clone(),
                    ));
                }
            }
        }
        let sparse_statement_matrix = SparsePolynomialMatrix::new(
            PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
                .expect("source ring should validate"),
            parameter_set.statement_rows,
            parameter_set.statement_columns,
            sparse_entries,
        )
        .expect("sparse statement matrix should validate");
        let sparse_generation = generate_sparse_linear_proof(SparseLinearProverProofInput {
            parameter_set: &parameter_set,
            proof_encoding: &proof_encoding,
            source_statement_matrix: &sparse_statement_matrix,
            target_vector_coefficients: &target_vector,
            matrix_coefficient_representation:
                LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
            target_coefficient_representation:
                LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
            source_witness_coefficients: &witness,
            public_randomness: &public_randomness,
            prover_randomness: &[12_u8; 32],
        })
        .expect("sparse proof generation should succeed");

        assert_eq!(sparse_generation.proof_bytes, dense_generation.proof_bytes);

        let verification =
            verify_sparse_linear_proof_components(SparseLinearProofVerificationInput {
                case_name: "generated-sparse-receiver-key-compatible-proof",
                parameter_set: &parameter_set,
                proof_encoding: &proof_encoding,
                public_randomness_hex: &to_hex(&public_randomness),
                source_statement_matrix: &sparse_statement_matrix,
                target_vector_coefficients: &target_vector,
                matrix_coefficient_representation:
                    LinearProofMatrixCoefficientRepresentation::CanonicalUnsignedSourceModulus,
                target_coefficient_representation:
                    LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
                proof_hex: &to_hex(&sparse_generation.proof_bytes),
                expected_proof_size_bytes: Some(sparse_generation.proof_bytes.len()),
            });

        assert_eq!(
            verification["ok"], true,
            "generated sparse proof should verify: {verification}"
        );
    }
}
