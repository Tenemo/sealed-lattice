use super::*;

#[test]
fn masked_claims_differ_under_fresh_proof_randomness() {
    // The published consistency claims are smudging-masked: two proofs of the
    // same statement under different proof randomness must publish different
    // claim values, and both must verify.
    let (statement, witness) =
        generate_development_public_key_share_instance("d00d2bad", SMALL_RING_DEGREE)
            .expect("public-key share instance");
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

#[test]
fn regenerated_limb_roots_preserve_encoded_proof_bytes_across_batch_sizes() {
    let (statement, witness) =
        generate_development_public_key_share_instance("cafe0002", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let serial_proof = prover::prove_evaluation_key_share_with_test_limb_batch_size(
        &statement,
        &witness,
        PROOF_RANDOMNESS_SEED,
        1,
    )
    .expect("serial prove");
    let partial_batch_proof = prover::prove_evaluation_key_share_with_test_limb_batch_size(
        &statement,
        &witness,
        PROOF_RANDOMNESS_SEED,
        2,
    )
    .expect("partial batch prove");
    let batched_proof = prover::prove_evaluation_key_share_with_test_limb_batch_size(
        &statement,
        &witness,
        PROOF_RANDOMNESS_SEED,
        3,
    )
    .expect("batched prove");

    let serial_proof_bytes = encode_trustee_evaluation_key_proof(&serial_proof);
    let partial_batch_proof_bytes = encode_trustee_evaluation_key_proof(&partial_batch_proof);
    let batched_proof_bytes = encode_trustee_evaluation_key_proof(&batched_proof);
    assert_eq!(
        serial_proof_bytes, partial_batch_proof_bytes,
        "two-pass limb regeneration must preserve the transcript and proof bytes with a partial trailing batch"
    );
    assert_eq!(
        serial_proof_bytes, batched_proof_bytes,
        "two-pass limb regeneration must preserve the transcript and proof bytes exactly"
    );
    verify_evaluation_key_share(&statement, &partial_batch_proof).expect("verify partial batch");
    verify_evaluation_key_share(&statement, &batched_proof).expect("verify");
}

#[test]
fn honest_public_key_share_proof_round_trips() {
    let (statement, witness) =
        generate_development_public_key_share_instance("a1b2c3d401", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    assert_eq!(statement.keys().len(), 1);
    assert_eq!(
        statement.keys()[0].kind,
        EvaluationKeyShareKind::PublicKeyShare
    );
    // The share spans every Q_share limb.
    assert_eq!(statement.limb_count(), DATA_PRIMES.len());
    assert_eq!(statement.family_shape().proof_family(), "public-key-share");
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
    tampered.keys_mut()[0].component_b_by_digit[0][0][0] ^= 1;
    let result = verify_evaluation_key_share(&tampered, &proof);
    assert!(result.is_err(), "a tampered share component must reject");
}

#[test]
fn public_key_share_rejects_a_secret_outside_the_committed_one() {
    // A trustee whose share secret differs from the bridge target secret
    // cannot prove: splicing another instance's target commitments makes the
    // committed-material relation fail at proving time.
    let (statement, witness) =
        generate_development_public_key_share_instance("dd44ee55", SMALL_RING_DEGREE)
            .expect("first instance");
    let (other_statement, _) =
        generate_development_public_key_share_instance("ff66aa77", SMALL_RING_DEGREE)
            .expect("second instance");
    let mut forged = statement;
    *forged
        .same_secret_bridge_mut()
        .expect("first bridge statement") = other_statement
        .same_secret_bridge()
        .expect("second bridge statement")
        .clone();
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
    forged.keys_mut()[0].key_switch_seed_hex = "00".repeat(64);
    let result = verify_evaluation_key_share(&forged, &proof);
    assert!(
        result.is_err(),
        "a foreign common reference polynomial must reject"
    );
}

#[test]
fn succinct_setup_statement_hash_vectors_pin_selected_families() {
    let same_secret_statement = super::super::commands::same_secret_bridge_statement_from_request(
        &same_secret_statement_hash_vector_request(),
    )
    .expect("same-secret statement vector");
    let same_secret = serde_json::json!({
        "proofFamily": same_secret_statement.family_shape().proof_family(),
        "statementHash": crate::hashing::to_hex(&same_secret_statement.statement_hash()),
    });
    let public_key_statement = super::super::commands::statement_from_request(
        &public_key_share_statement_hash_vector_request(),
    )
    .expect("public-key statement vector");
    let public_key = serde_json::json!({
        "proofFamily": public_key_statement.family_shape().proof_family(),
        "statementHash": crate::hashing::to_hex(&public_key_statement.statement_hash()),
    });
    let (_private_vss, private_vss_statement_hash) =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_statement_hash_vector_request(),
        )
        .expect("private VSS statement vector");
    // The key-bearing family proves through the atom schedule and carries an
    // exact source commitment linkage, so the statement-hash vector pins the
    // parsed statement's hash directly.
    let trustee_evaluation_key_statement = super::super::commands::statement_from_request(
        &trustee_evaluation_key_statement_hash_vector_request(),
    )
    .expect("trustee evaluation-key statement vector");
    let trustee_evaluation_key = serde_json::json!({
        "proofFamily": trustee_evaluation_key_statement.family_shape().proof_family(),
        "statementHash":
            crate::hashing::to_hex(&trustee_evaluation_key_statement.statement_hash()),
    });

    println!(
        "statement hash vectors: same-secret={}, public-key-share={}, private-vss-share={}, trustee-evaluation-key={}",
        same_secret["statementHash"]
            .as_str()
            .expect("same-secret hash"),
        public_key["statementHash"]
            .as_str()
            .expect("public-key hash"),
        private_vss_statement_hash,
        trustee_evaluation_key["statementHash"]
            .as_str()
            .expect("trustee evaluation-key hash"),
    );
    let expected_statement_hashes = expected_statement_hash_vectors();
    assert_eq!(same_secret["proofFamily"], "same-secret-bridge");
    assert_eq!(
        same_secret["statementHash"],
        expected_statement_hashes["sameSecretBridge"]
    );
    assert_eq!(public_key["proofFamily"], "public-key-share");
    assert_eq!(
        public_key["statementHash"],
        expected_statement_hashes["publicKeyShare"]
    );
    assert_eq!(
        private_vss_statement_hash,
        expected_statement_hashes["privateVssShare"]
    );
    assert_eq!(
        trustee_evaluation_key["proofFamily"],
        "trustee-evaluation-key"
    );
    assert_eq!(
        trustee_evaluation_key["statementHash"],
        expected_statement_hashes["trusteeEvaluationKey"]
    );
}
