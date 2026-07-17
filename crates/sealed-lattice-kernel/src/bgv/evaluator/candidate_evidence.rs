//! Selected evaluator parameters consumed by proof-profile construction.

use crate::{
    bgv::parameters::{DATA_PRIMES, PLAINTEXT_MODULUS, SPECIAL_PRIMES},
    encoding::CanonicalResult,
    foundation::FOUNDATION_PROFILE,
};

use super::top_k::{SELECTED_EVALUATOR_WORKING_LEVEL, selected_evaluator_rotation_key_schedule};

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct EvaluatorCandidateInput {
    pub(crate) data_primes: Vec<u64>,
    pub(crate) special_primes: Vec<u64>,
    pub(crate) plaintext_modulus: u64,
    pub(crate) evaluator_working_level: usize,
    pub(crate) relinearization_levels: Vec<usize>,
    pub(crate) galois_key_schedule: Vec<(usize, usize)>,
}

impl EvaluatorCandidateInput {
    pub(crate) fn implemented() -> CanonicalResult<Self> {
        Ok(Self {
            data_primes: DATA_PRIMES.to_vec(),
            special_primes: SPECIAL_PRIMES.to_vec(),
            plaintext_modulus: PLAINTEXT_MODULUS,
            evaluator_working_level: SELECTED_EVALUATOR_WORKING_LEVEL,
            relinearization_levels: vec![SELECTED_EVALUATOR_WORKING_LEVEL],
            galois_key_schedule: selected_evaluator_rotation_key_schedule(usize::from(
                FOUNDATION_PROFILE.option_count,
            ))?,
        })
    }
}
