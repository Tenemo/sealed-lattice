#[cfg(test)]
mod aggregation;
#[cfg(test)]
mod encryption;
mod request;
#[cfg(test)]
use aggregation::*;
#[cfg(test)]
use encryption::*;
pub(crate) use request::direct_ballot_slots;

use crate::foundation::FOUNDATION_PROFILE;

#[cfg(test)]
use crate::bgv::{
    evaluator::engine::{ciphertext_add, encode_slots_to_coefficients},
    parameters::{PLAINTEXT_MODULUS, POLYNOMIAL_DEGREE},
};

#[cfg(test)]
use crate::{
    bgv::evaluator::engine::{Ciphertext, DevelopmentBgvKey},
    encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult},
    hashing::hash512_hex,
};

const OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
#[cfg(test)]
const PAIR_COUNT: usize = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
// pub(crate): the setup-parameter identity binds the bounded-domain evaluator
// profile (score span times roster size) from these score-domain constants.
pub(crate) const MINIMUM_SCORE: u64 = FOUNDATION_PROFILE.minimum_score as u64;
pub(crate) const MAXIMUM_SCORE: u64 = FOUNDATION_PROFILE.maximum_score as u64;
#[cfg(test)]
const SCORE_BUCKET_COUNT: usize = (MAXIMUM_SCORE - MINIMUM_SCORE + 1) as usize;

#[cfg(test)]
#[derive(Clone)]
struct DirectBallotInput {
    scores: Vec<u64>,
    one_hot_witnesses: Option<Vec<Vec<u64>>>,
    encryption_seed_hex: String,
}

#[cfg(test)]
#[derive(Clone)]
struct DirectEncryptedBallot {
    ciphertext: Ciphertext,
}

#[cfg(test)]
mod tests;
