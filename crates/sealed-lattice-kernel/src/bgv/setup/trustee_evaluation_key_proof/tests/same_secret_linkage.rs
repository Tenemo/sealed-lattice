use super::*;

#[test]
fn honest_proof_with_same_secret_linkage_round_trips() {
    // Level two keeps all three commitment fields active and must carry
    // exactly one same-secret commitment for each active Q_share limb.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "11aa22bb",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    assert!(statement.same_secret_linkage.is_some());
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn same_secret_linkage_rejects_commitments_outside_active_limb_set() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "11aa22cc",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(4),
    )
    .expect("development instance");

    assert!(
        statement.validate_shape().is_err(),
        "extra same-secret linkage commitments must not be accepted outside the active Q_share limb set"
    );
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "proving must refuse a statement whose linkage commitment count does not match the theorem shape"
    );
}

#[test]
fn batched_schedule_with_linkage_round_trips() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "33cc44dd",
        &[round_one(2), round_two(2), rotation(3, 2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn same_secret_linkage_anchor_proof_round_trips_without_keys() {
    // The keyless statement is the per-trustee same-secret linkage anchor:
    // it opens one constant commitment per Q_share limb while the committed
    // rows are checked over the three setup commitment fields.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "99ffeedd",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    assert!(statement.keys.is_empty());
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");

    let encoded = encode_trustee_evaluation_key_proof(&proof);
    let decoded =
        decode_trustee_evaluation_key_proof(&statement, &encoded).expect("decode anchor proof");
    verify_evaluation_key_share(&statement, &decoded).expect("verify decoded");
}

#[test]
fn same_secret_anchor_rejects_partial_q_share_commitment_set() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "77aaccee",
        &[],
        SMALL_RING_DEGREE,
        Some(SETUP_COMMITMENT_MODULUS_LIMB_INDICES.len()),
    )
    .expect("partial anchor instance");

    assert!(
        statement.validate_shape().is_err(),
        "the keyless same-secret anchor must not accept only the setup commitment-field count"
    );
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "proving must refuse a partial same-secret anchor commitment set"
    );
}

#[test]
fn keyless_statement_without_linkage_is_refused() {
    let (mut statement, witness) = generate_development_trustee_instance_with_linkage(
        "aa00bb11",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    statement.same_secret_linkage = None;
    assert!(
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "a statement with neither keys nor the linkage anchor must be refused"
    );
}

#[test]
fn anchor_rejects_commitments_to_a_different_secret() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cc22dd33",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    let (other_statement, _) = generate_development_trustee_instance_with_linkage(
        "ee44ff55",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("second anchor instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    assert!(
        prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED).is_err(),
        "anchor proving must reject commitments that open to a different secret"
    );
}

#[test]
fn linkage_rejects_commitments_to_a_different_secret() {
    // A trustee whose key-relation secret differs from the committed secret
    // must not be able to produce a proof: the commitment-opening relations
    // fail, so the sumcheck remainder is nonzero at proving time.
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "55ee66ff",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("first instance");
    let (other_statement, _) = generate_development_trustee_instance_with_linkage(
        "7788aabb",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("second instance");
    let mut forged = statement;
    forged.same_secret_linkage = other_statement.same_secret_linkage;
    let result = prove_evaluation_key_share(&forged, &witness, PROOF_RANDOMNESS_SEED);
    assert!(
        result.is_err(),
        "proving must reject commitments that open to a different secret"
    );
}

#[test]
fn tampered_linkage_commitment_is_rejected() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "99ffaa00",
        &[round_one(2)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    let mut tampered = statement;
    let linkage = tampered
        .same_secret_linkage
        .as_mut()
        .expect("linkage present");
    let modulus = linkage.commitments[0].limbs[0].modulus;
    linkage.commitments[0].limbs[0].rows[0][0] =
        (linkage.commitments[0].limbs[0].rows[0][0] + 1) % modulus;
    let result = verify_evaluation_key_share(&tampered, &proof);
    assert!(result.is_err(), "tampered linkage commitment must reject");
}
