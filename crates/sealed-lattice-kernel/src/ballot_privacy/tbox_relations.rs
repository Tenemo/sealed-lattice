use super::*;
use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

#[cfg(test)]
use super::linear_proof_public_parameters::DEFAULT_LINEAR_PROOF_COEFFICIENT_MODULUS;
use super::{
    linear_proof_public_parameters::{DEFAULT_LINEAR_PROOF_RING_DEGREE, TBOX_SHORT_MESSAGE_LENGTH},
    linear_proof_rng::sample_linear_proof_uniform_u64_values,
    polynomial_matrix::PolynomialMatrix,
    polynomial_ring::PolynomialRing,
    polynomial_vector::PolynomialVector,
    quadratic_equation::{LinearProofQuadraticEquation, WeightedLinearProofQuadraticEquation},
    sparse_polynomial_matrix::{SparsePolynomialMatrix, SparsePolynomialMatrixEntry},
    sparse_polynomial_vector::{SparsePolynomialVector, SparsePolynomialVectorEntry},
};

#[cfg(test)]
pub(super) use super::linear_proof_profile_constants as profile_constants;
pub(super) use super::{
    linear_proof_parameters as parameters, linear_proof_public_parameters as public_parameters,
    linear_proof_rng as rng,
};

#[path = "linear_proof/tbox_relations/norm_relations.rs"]
mod norm_relations;
#[path = "linear_proof/tbox_relations/response_relations.rs"]
mod response_relations;
#[path = "linear_proof/tbox_relations/tbox_accumulators.rs"]
mod tbox_accumulators;

pub(crate) use norm_relations::*;
pub(crate) use response_relations::*;
pub(crate) use tbox_accumulators::*;

#[cfg(test)]
pub(crate) use norm_relations::{
    tbox_proof_ring as linear_proof_tbox_proof_ring,
    tbox_quadratic_many_dimension as linear_proof_tbox_quadratic_many_dimension,
};
