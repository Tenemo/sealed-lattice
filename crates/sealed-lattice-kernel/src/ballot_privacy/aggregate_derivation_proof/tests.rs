use super::relation_proof::{aggregate_relation_challenge_scalar, reduce_unbiased_u64};
use super::{
    AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT, AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS,
    AGGREGATE_DERIVATION_PROOF_MODULUS,
};

#[test]
fn aggregate_derivation_unbiased_reduction_rejects_overhang_samples() {
    assert_eq!(reduce_unbiased_u64(0, 3), Some(0));
    assert_eq!(reduce_unbiased_u64(1, 3), Some(1));
    assert_eq!(reduce_unbiased_u64(2, 3), Some(2));
    assert_eq!(reduce_unbiased_u64(u64::MAX - 1, 3), Some(2));
    assert_eq!(reduce_unbiased_u64(u64::MAX, 3), None);
    assert_eq!(reduce_unbiased_u64(7, 0), None);
}

#[test]
fn aggregate_derivation_repeats_field_challenges_to_reach_target_soundness() {
    assert_eq!(AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT, 3);
    let computed_challenge_soundness_bits =
        u64::try_from(AGGREGATE_DERIVATION_CHALLENGE_REPETITION_COUNT)
            .expect("aggregate derivation repetition count fits u64")
            * u64::from(AGGREGATE_DERIVATION_PROOF_MODULUS.ilog2());
    assert_eq!(
        AGGREGATE_DERIVATION_CHALLENGE_SOUNDNESS_BITS,
        computed_challenge_soundness_bits
    );
    assert!(computed_challenge_soundness_bits >= 128);
    let first_challenge = aggregate_relation_challenge_scalar(
        "statement-digest",
        "11",
        &[vec![0, 1, 2]],
        AGGREGATE_DERIVATION_PROOF_MODULUS,
        0,
    )
    .expect("first aggregate derivation challenge should derive");
    let second_challenge = aggregate_relation_challenge_scalar(
        "statement-digest",
        "11",
        &[vec![0, 1, 2]],
        AGGREGATE_DERIVATION_PROOF_MODULUS,
        1,
    )
    .expect("second aggregate derivation challenge should derive");

    assert!((1..AGGREGATE_DERIVATION_PROOF_MODULUS).contains(&first_challenge));
    assert!((1..AGGREGATE_DERIVATION_PROOF_MODULUS).contains(&second_challenge));
}
