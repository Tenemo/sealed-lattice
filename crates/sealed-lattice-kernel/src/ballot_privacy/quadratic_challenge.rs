use super::*;

pub(super) use super::{
    linear_proof_parameters as parameters, linear_proof_public_parameters as public_parameters,
    linear_proof_rng as rng, linear_proof_transcript as transcript,
};

#[path = "linear_proof/quadratic_challenge/challenge_verifier.rs"]
mod challenge_verifier;

pub(crate) use challenge_verifier::validate_quadratic_challenge;
#[cfg(test)]
pub(crate) use challenge_verifier::{
    gamma_decompression_high_bits, short_response_l2_bound_squared,
};

#[cfg(test)]
#[path = "linear_proof/quadratic_challenge/challenge_tests.rs"]
mod challenge_tests;
