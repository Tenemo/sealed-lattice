use super::{
    ConstantCoefficientSparseMatrixEntry, LinearProofTargetCoefficientRepresentation,
    PolynomialRing, SparsePolynomialMatrix, SparsePolynomialMatrixEntry,
    build_constant_coefficient_sparse_source_matrix,
    derive_dense_compatible_sparse_linear_statement_transcript,
    derive_sparse_linear_statement_transcript, transform_sparse_statement_matrix_to_proof_ring,
    transform_sparse_target_vector_to_proof_ring,
};
use crate::ballot_privacy::{
    linear_proof::parameters::{LinearProofParameterSet, demo_linear_proof_encoding_contract},
    linear_proof::statement::{
        derive_linear_statement_transcript, derive_transformed_statement_matrix,
        derive_transformed_target_vector,
    },
};

fn sparse_test_parameters() -> LinearProofParameterSet {
    LinearProofParameterSet {
        profile_id: "unit-sparse-linear-statement-v1".to_string(),
        source: "unit-test".to_string(),
        relation: "A*w + t = 0".to_string(),
        ring_degree: 8,
        proof_system_ring_degree: 4,
        coefficient_modulus: 17,
        statement_rows: 2,
        statement_columns: 3,
        witness_l2_bound_squared: 64,
        expected_proof_size_bytes: None,
    }
}

fn sparse_test_proof_encoding()
-> crate::ballot_privacy::linear_proof::parameters::LinearProofEncoding {
    let mut proof_encoding = demo_linear_proof_encoding_contract();
    proof_encoding.ring_degree = 4;
    proof_encoding.coefficient_modulus = 97;
    proof_encoding.full_size_coefficient_bit_length = 7;
    proof_encoding.compressed_coefficient_bit_length = 6;

    proof_encoding
}

fn sparse_test_matrix() -> SparsePolynomialMatrix {
    let parameter_set = sparse_test_parameters();
    SparsePolynomialMatrix::new(
        PolynomialRing::new(parameter_set.ring_degree, parameter_set.coefficient_modulus)
            .expect("source ring should validate"),
        parameter_set.statement_rows,
        parameter_set.statement_columns,
        vec![
            SparsePolynomialMatrixEntry::new(0, 1, vec![1, 0, 2, 0, 3, 0, 4, 0]),
            SparsePolynomialMatrixEntry::new(1, 0, vec![0, 5, 0, 6, 0, 7, 0, 8]),
            SparsePolynomialMatrixEntry::new(1, 2, vec![9, 0, 0, 1, 0, 0, 2, 0]),
        ],
    )
    .expect("sparse test matrix should validate")
}

fn dense_test_matrix() -> Vec<Vec<Vec<u64>>> {
    let parameter_set = sparse_test_parameters();
    let mut dense_matrix =
        vec![
            vec![vec![0_u64; parameter_set.ring_degree]; parameter_set.statement_columns];
            parameter_set.statement_rows
        ];
    for entry in sparse_test_matrix().entries() {
        dense_matrix[entry.row_index()][entry.column_index()] = entry.coefficients().to_vec();
    }

    dense_matrix
}

fn target_vector() -> Vec<Vec<u64>> {
    vec![
        vec![0, 1, 16, 2, 15, 3, 14, 4],
        vec![5, 0, 6, 0, 7, 0, 8, 0],
    ]
}

#[test]
fn builds_sparse_source_matrix_from_compact_constant_entries() {
    let parameter_set = sparse_test_parameters();
    let source_matrix = build_constant_coefficient_sparse_source_matrix(
        &parameter_set,
        &[
            ConstantCoefficientSparseMatrixEntry {
                row_index: 0,
                column_index: 1,
                constant_coefficient: 7,
            },
            ConstantCoefficientSparseMatrixEntry {
                row_index: 1,
                column_index: 2,
                constant_coefficient: 9,
            },
        ],
    )
    .expect("compact sparse matrix should expand");

    assert_eq!(source_matrix.entries().len(), 2);
    assert_eq!(
        source_matrix.entries()[0].coefficients(),
        &[7, 0, 0, 0, 0, 0, 0, 0]
    );
    assert!(
        build_constant_coefficient_sparse_source_matrix(
            &parameter_set,
            &[ConstantCoefficientSparseMatrixEntry {
                row_index: 0,
                column_index: 0,
                constant_coefficient: 17,
            }],
        )
        .expect_err("noncanonical coefficient should fail")
        .message
        .contains("not canonical")
    );
}

#[test]
fn sparse_statement_transform_matches_dense_transform() {
    let parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let sparse_matrix = sparse_test_matrix();
    let transformed_sparse_matrix = transform_sparse_statement_matrix_to_proof_ring(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
    )
    .expect("sparse statement should transform");
    let transformed_dense_matrix = derive_transformed_statement_matrix(
        &parameter_set,
        &proof_encoding,
        &dense_test_matrix(),
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("dense statement should transform");

    assert_eq!(
        transformed_sparse_matrix
            .to_dense()
            .expect("sparse transformed matrix should densify"),
        transformed_dense_matrix
    );
}

#[test]
fn sparse_target_transform_matches_dense_target_transform() {
    let parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let transformed_sparse_target = transform_sparse_target_vector_to_proof_ring(
        &parameter_set,
        &proof_encoding,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
    )
    .expect("sparse target should transform");
    let transformed_dense_target = derive_transformed_target_vector(
        &parameter_set,
        &proof_encoding,
        &dense_test_matrix(),
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CenteredSignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("dense target should transform");

    assert_eq!(transformed_sparse_target, transformed_dense_target);
}

#[test]
fn sparse_statement_transcript_binds_entry_position_target_and_randomness() {
    let parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let sparse_matrix = sparse_test_matrix();
    let transcript = derive_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("sparse transcript should derive");
    let mut moved_entry_matrix_entries = sparse_matrix.entries().to_vec();
    moved_entry_matrix_entries[0] = SparsePolynomialMatrixEntry::new(
        0,
        0,
        moved_entry_matrix_entries[0].coefficients().to_vec(),
    );
    moved_entry_matrix_entries.sort_by_key(|entry| (entry.row_index(), entry.column_index()));
    let moved_entry_matrix = SparsePolynomialMatrix::new(
        sparse_matrix.ring(),
        sparse_matrix.rows(),
        sparse_matrix.columns(),
        moved_entry_matrix_entries,
    )
    .expect("moved sparse matrix should validate");
    let moved_entry_transcript = derive_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &moved_entry_matrix,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("moved sparse transcript should derive");
    let mut changed_target = target_vector();
    changed_target[0][0] = 1;
    let changed_target_transcript = derive_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
        &changed_target,
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("changed target transcript should derive");
    let wrong_randomness_transcript = derive_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[4_u8; 32],
    )
    .expect("wrong randomness transcript should derive");

    assert_eq!(transcript.transformed_statement_matrix_rows, 4);
    assert_eq!(transcript.transformed_statement_matrix_columns, 6);
    assert_ne!(
        transcript.sparse_arithmetic_statement_hash_hex,
        moved_entry_transcript.sparse_arithmetic_statement_hash_hex
    );
    assert_ne!(
        transcript.sparse_arithmetic_statement_hash_hex,
        changed_target_transcript.sparse_arithmetic_statement_hash_hex
    );
    assert_eq!(transcript.sparse_arithmetic_statement_hash_hex.len(), 64);
    assert_ne!(
        transcript.public_parameters_and_statement_hash_hex,
        wrong_randomness_transcript.public_parameters_and_statement_hash_hex
    );
}

#[test]
fn rejects_sparse_statement_shape_mismatches() {
    let mut parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let sparse_matrix = sparse_test_matrix();
    parameter_set.statement_rows = 3;

    let error = transform_sparse_statement_matrix_to_proof_ring(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
    )
    .expect_err("row mismatch should fail");

    assert!(error.message.contains("dimensions"));
}

#[test]
fn dense_and_sparse_transcripts_are_intentionally_separate_domains() {
    let parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let sparse_matrix = sparse_test_matrix();
    let sparse_transcript = derive_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("sparse transcript should derive");
    let dense_transcript = derive_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &dense_test_matrix(),
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("dense transcript should derive");

    assert_ne!(
        sparse_transcript.sparse_arithmetic_statement_hash_hex,
        dense_transcript.arithmetic_statement_hash_hex
    );
    assert_ne!(
        sparse_transcript.public_parameters_and_statement_hash_hex,
        dense_transcript.public_parameters_and_statement_hash_hex
    );
}

#[test]
fn dense_compatible_sparse_transcript_matches_dense_transcript_without_dense_matrix() {
    let parameter_set = sparse_test_parameters();
    let proof_encoding = sparse_test_proof_encoding();
    let sparse_matrix = sparse_test_matrix();
    let sparse_transcript = derive_dense_compatible_sparse_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &sparse_matrix,
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("dense-compatible sparse transcript should derive");
    let dense_transcript = derive_linear_statement_transcript(
        &parameter_set,
        &proof_encoding,
        &dense_test_matrix(),
        &target_vector(),
        LinearProofTargetCoefficientRepresentation::CanonicalUnsignedSourceModulus,
        &[3_u8; 32],
    )
    .expect("dense transcript should derive");

    assert_eq!(
        sparse_transcript.arithmetic_statement_hash_hex,
        dense_transcript.arithmetic_statement_hash_hex
    );
    assert_eq!(
        sparse_transcript.public_parameters_and_statement_hash_hex,
        dense_transcript.public_parameters_and_statement_hash_hex
    );
    assert_eq!(
        sparse_transcript.encoded_statement_bytes,
        dense_transcript.encoded_statement_bytes
    );
}
