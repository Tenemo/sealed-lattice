mod request;
pub(crate) use request::{
    PAIR_CHARACTER_AUXILIARY_COUNT, PAIR_CHARACTER_CIPHERTEXT_COUNT, PAIR_CHARACTER_LANE_COUNT,
    PAIR_CHARACTER_LANE_DEGREE, PAIR_CHARACTER_PLAINTEXT_MODULUS, PAIR_CHARACTER_RING_DEGREE,
    PairCharacterEncoderProfileTerm, SCORE_BUCKET_COUNT, pair_character_encoder_profile_sequence,
    pair_character_encoder_profile_terms, pair_character_lane_assignments,
    pair_character_lane_idempotent_coefficients, pair_character_lane_value,
    pair_character_plaintexts,
};

use crate::foundation::FOUNDATION_PROFILE;

const OPTION_COUNT: usize = FOUNDATION_PROFILE.option_count as usize;
// pub(crate): the setup-parameter identity binds the bounded-domain evaluator
// profile (score span times roster size) from these score-domain constants.
pub(crate) const MINIMUM_SCORE: u64 = FOUNDATION_PROFILE.minimum_score as u64;
pub(crate) const MAXIMUM_SCORE: u64 = FOUNDATION_PROFILE.maximum_score as u64;

#[cfg(test)]
mod tests;
