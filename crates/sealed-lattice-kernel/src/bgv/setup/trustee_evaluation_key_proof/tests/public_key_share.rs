use super::*;

#[test]
fn honest_public_key_share_proof_round_trips() {
    let (statement, witness) =
        generate_development_public_key_share_instance("a1b2c3d401", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    assert_eq!(statement.keys.len(), 1);
    assert_eq!(
        statement.keys[0].kind,
        EvaluationKeyShareKind::PublicKeyShare
    );
    // The share spans every Q_share limb.
    assert_eq!(statement.limb_count(), DATA_PRIMES.len());
    assert_eq!(statement.context.proof_family, "public-key-share");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    assert_eq!(proof.limb_proofs.len(), DATA_PRIMES.len());
    verify_evaluation_key_share(&statement, &proof).expect("verify");

    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let decoded = decode_trustee_evaluation_key_proof(&statement, &encoded)
        .expect("decode public-key share proof");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded");
}

#[test]
fn public_key_share_rejects_tampered_share_component() {
    let (statement, witness) =
        generate_development_public_key_share_instance("bb22cc33", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    // Flip one published share coefficient: the share relation no longer holds
    // in that limb field, so the verifier rebuilds a different statement.
    let mut tampered = statement;
    tampered.keys[0].component_b_by_digit[0][0][0] ^= 1;
    let result = verify_evaluation_key_share(&tampered, &proof);
    assert!(result.is_err(), "a tampered share component must reject");
}

#[test]
fn public_key_share_rejects_a_secret_outside_the_committed_one() {
    // A trustee whose share secret differs from the anchored committed secret
    // cannot prove: splicing another instance's commitment makes the linkage
    // opening relation fail at proving time.
    let (statement, witness) =
        generate_development_public_key_share_instance("dd44ee55", SMALL_RING_DEGREE)
            .expect("first instance");
    let (other_statement, _) =
        generate_development_public_key_share_instance("ff66aa77", SMALL_RING_DEGREE)
            .expect("second instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    assert!(
        prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "a share secret that does not open the committed value must not prove"
    );
}

#[test]
fn public_key_share_rejects_a_foreign_common_reference_polynomial() {
    // The public sample is the seed-derived common reference polynomial. A
    // statement whose seed (key_switch_seed_hex) is swapped recomputes a
    // different a_l, so the honest proof no longer verifies.
    let (statement, witness) =
        generate_development_public_key_share_instance("aa11bb2201", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut forged = statement;
    forged.keys[0].key_switch_seed_hex = "00".repeat(64);
    let result = verify_evaluation_key_share(&forged, &proof);
    assert!(
        result.is_err(),
        "a foreign common reference polynomial must reject"
    );
}
