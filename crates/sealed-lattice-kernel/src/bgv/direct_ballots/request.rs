use super::*;

pub(super) fn direct_ballot_slots(scores: &[u64]) -> Vec<u64> {
    let mut slots = vec![0_u64; POLYNOMIAL_DEGREE];
    slots[..OPTION_COUNT].copy_from_slice(scores);
    slots
}
