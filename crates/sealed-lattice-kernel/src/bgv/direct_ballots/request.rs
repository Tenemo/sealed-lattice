use crate::encoding::{CanonicalError, CanonicalErrorCode, CanonicalResult};

use super::OPTION_COUNT;

/// Encodes every unordered option pair as `lower score - higher score`, in
/// shift-major order and then by the lower option ordinal.
pub(crate) fn direct_ballot_slots(
    scores: &[u64],
    plaintext_modulus: u64,
    ring_degree: usize,
) -> CanonicalResult<Vec<u64>> {
    let pair_count = OPTION_COUNT * (OPTION_COUNT - 1) / 2;
    if scores.len() != OPTION_COUNT || plaintext_modulus < 2 || ring_degree < pair_count {
        return Err(CanonicalError::new(
            CanonicalErrorCode::MalformedLength,
            "direct ballot pair packing received incompatible score or ring geometry",
        ));
    }
    if scores.iter().any(|score| *score >= plaintext_modulus) {
        return Err(CanonicalError::new(
            CanonicalErrorCode::InvalidProtocolObject,
            "direct ballot score is outside the plaintext field",
        ));
    }

    let mut slots = vec![0_u64; ring_degree];
    let mut pair_slot_ordinal = 0_usize;
    for shift in 1..OPTION_COUNT {
        for lower_option_ordinal in 0..OPTION_COUNT - shift {
            let higher_option_ordinal = lower_option_ordinal + shift;
            let lower_score = scores[lower_option_ordinal];
            let higher_score = scores[higher_option_ordinal];
            slots[pair_slot_ordinal] = if lower_score >= higher_score {
                lower_score - higher_score
            } else {
                plaintext_modulus - (higher_score - lower_score)
            };
            pair_slot_ordinal += 1;
        }
    }
    Ok(slots)
}
