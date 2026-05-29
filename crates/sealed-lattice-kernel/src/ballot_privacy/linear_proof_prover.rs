use super::*;
use crate::{encoding::CanonicalResult, hashing::to_hex};

use super::{
    abdlop_commitment::encode_compressed_commitment_vector,
    linear_proof_parameters::{
        LinearProofEncoding, LinearProofParameterSet, linear_proof_profile_for_encoding,
    },
    linear_proof_public_parameters::derive_abdlop_public_parameters,
    linear_proof_rng::{
        generate_linear_proof_aes256ctr_stream,
        sample_linear_proof_autostable_challenge_coefficients,
        sample_linear_proof_uniform_u64_values,
    },
    linear_proof_statement::{StreamedLinearProofStatement, source_polynomial_split_factor},
    linear_proof_transcript::{shake128_32, shake128_96},
    many_quadratic::{build_many_quadratic_equations, fold_many_quadratic_equations},
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    proof_coder::{LinearProofComponents, encode_linear_proof_components},
    quadratic_equation::LinearProofQuadraticEquation,
    sparse_linear_proof_statement::{
        derive_dense_compatible_sparse_linear_statement_transcript_with_matrix_coefficient_representation,
        transform_sparse_statement_matrix_to_proof_ring_with_coefficient_representation,
        transform_sparse_target_vector_to_proof_ring,
    },
    tbox_relations::{
        apply_tbox_z3_response_relations_for_statement_shape,
        apply_tbox_z3_response_relations_sparse, apply_tbox_z4_response_relations_sparse,
        apply_tbox_z4_response_relations_with_product_builder, build_tbox_prefix_accumulators,
    },
};

pub(super) use super::{
    linear_proof_parameters as parameters, linear_proof_public_parameters as public_parameters,
    linear_proof_rng as rng, linear_proof_statement as statement,
    linear_proof_transcript as transcript, sparse_linear_proof_statement as sparse_statement,
};

#[path = "linear_proof/prover/prover_preparation.rs"]
mod prover_preparation;
#[path = "linear_proof/prover/quadratic_witness.rs"]
mod quadratic_witness;
#[path = "linear_proof/prover/tbox_witness.rs"]
mod tbox_witness;

pub(crate) use prover_preparation::*;
use quadratic_witness::*;
pub(crate) use tbox_witness::*;

#[cfg(test)]
#[path = "linear_proof/prover/proof_generation_tests.rs"]
mod proof_generation_tests;
