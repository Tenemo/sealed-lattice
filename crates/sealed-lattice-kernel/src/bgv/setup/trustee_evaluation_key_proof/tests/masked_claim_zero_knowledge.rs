use super::*;

#[test]
fn masked_claims_differ_under_fresh_proof_randomness() {
    // The published consistency claims are smudging-masked: two proofs of the
    // same statement under different proof randomness must publish different
    // claim values, and both must verify.
    let (statement, witness) =
        generate_development_trustee_instance("d00d2bad", &[round_one(1)], SMALL_RING_DEGREE)
            .expect("development instance");
    let first =
        prove_evaluation_key_share(&statement, &witness, "aaaaaaaaaaaaaaaa").expect("prove first");
    let second =
        prove_evaluation_key_share(&statement, &witness, "bbbbbbbbbbbbbbbb").expect("prove second");
    verify_evaluation_key_share(&statement, &first).expect("verify first");
    verify_evaluation_key_share(&statement, &second).expect("verify second");
    assert_ne!(
        first.limb_proofs[0].masked_consistency_claims,
        second.limb_proofs[0].masked_consistency_claims,
        "masked claims must depend on the proof randomness"
    );
}
