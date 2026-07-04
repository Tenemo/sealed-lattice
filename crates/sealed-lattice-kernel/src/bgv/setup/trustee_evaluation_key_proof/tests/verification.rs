use super::*;

#[test]
fn honest_round_one_relinearization_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("a1b2c3d4", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn honest_round_two_relinearization_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("f00dface", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn honest_galois_rotation_proof_round_trips() {
    let (statement, witness) =
        generate_development_trustee_instance("0badf00d", &[rotation(3, 2)], SMALL_RING_DEGREE)
            .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

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

#[test]
fn batched_trustee_schedule_round_trips_with_mixed_levels() {
    // One batched proof covering relinearization rounds one and two plus two
    // rotations, with one rotation at a lower level so per-limb active key
    // sets differ across limbs.
    let (statement, witness) = generate_development_trustee_instance(
        "cafe0001",
        &[round_one(2), round_two(2), rotation(3, 2), rotation(5, 1)],
        SMALL_RING_DEGREE,
    )
    .expect("development instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("prove");
    assert_eq!(proof.limb_proofs.len(), 3);
    verify_evaluation_key_share(&statement, &proof).expect("verify");
}

#[test]
fn regenerated_limb_roots_preserve_encoded_proof_bytes_across_batch_sizes() {
    let (statement, witness) = generate_development_trustee_instance(
        "cafe0002",
        &[round_one(2), round_two(2), rotation(3, 2), rotation(5, 1)],
        SMALL_RING_DEGREE,
    )
    .expect("development instance");
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
fn multi_trustee_ceremony_slice_round_trips_with_recomputed_aggregate() {
    // Three trustees, each with round-one and round-two relinearization
    // shares and same-secret linkage; every round-two source multiplies the
    // trustee secret by the public aggregate recomputed from the accepted
    // round-one components, the multi-party-realizable flow the package
    // verifier rebinds.
    let instances =
        generate_development_trustee_ceremony_slice("ceremony01", 3, 2, SMALL_RING_DEGREE, 3)
            .expect("ceremony slice");
    assert_eq!(instances.len(), 3);
    for (statement, witness) in &instances {
        assert_eq!(statement.keys.len(), 2);
        assert_eq!(
            statement.keys[1].kind,
            EvaluationKeyShareKind::RelinearizationRoundTwo
        );
        let proof = prove_evaluation_key_share(statement, witness, PROOF_RANDOMNESS_SEED)
            .expect("prove trustee");
        verify_evaluation_key_share(statement, &proof).expect("verify trustee");
    }
    // A tampered aggregate (one residue off in one trustee's round-two
    // statement) must reject: the verifier recomputes the aggregate itself,
    // so a prover cannot substitute a different one.
    let (mut tampered_statement, tampered_witness) =
        generate_development_trustee_ceremony_slice("ceremony01", 3, 2, SMALL_RING_DEGREE, 3)
            .expect("ceremony slice")
            .into_iter()
            .next()
            .expect("first trustee");
    let modulus = tampered_statement.limb_moduli()[0];
    tampered_statement.keys[1].round_one_aggregate_diagonal[0][0] =
        (tampered_statement.keys[1].round_one_aggregate_diagonal[0][0] + 1) % modulus;
    assert!(
        prove_evaluation_key_share(
            &tampered_statement,
            &tampered_witness,
            PROOF_RANDOMNESS_SEED
        )
        .is_err(),
        "a substituted aggregate must not prove"
    );
}

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

#[test]
fn succinct_setup_statement_hash_vectors_cover_current_families() {
    let same_secret = super::generate_trustee_evaluation_key_proof_from_request(
        &same_secret_statement_hash_vector_request(),
    )
    .expect("same-secret statement vector");
    let public_key = super::generate_trustee_evaluation_key_proof_from_request(
        &public_key_share_statement_hash_vector_request(),
    )
    .expect("public-key statement vector");
    let private_vss =
        crate::bgv::setup::private_vss::generate_private_vss_share_proof_from_request(
            &private_vss_statement_hash_vector_request(),
        )
        .expect("private VSS statement vector");
    let trustee_evaluation_key = super::generate_trustee_evaluation_key_proof_from_request(
        &trustee_evaluation_key_statement_hash_vector_request(),
    )
    .expect("trustee evaluation-key statement vector");

    println!(
        "statement hash vectors: same-secret={}, public-key-share={}, private-vss-share={}, trustee-evaluation-key={}",
        same_secret["statementHash"]
            .as_str()
            .expect("same-secret hash"),
        public_key["statementHash"]
            .as_str()
            .expect("public-key hash"),
        private_vss["privateVssShareProof"]["statementHash"]
            .as_str()
            .expect("private VSS hash"),
        trustee_evaluation_key["statementHash"]
            .as_str()
            .expect("trustee evaluation-key hash"),
    );
    let expected_statement_hashes = expected_statement_hash_vectors();
    assert_eq!(same_secret["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(
        same_secret["statementHash"],
        expected_statement_hashes["sameSecret"]
    );
    assert_eq!(public_key["proofFamily"], "public-key-share");
    assert_eq!(
        public_key["statementHash"],
        expected_statement_hashes["publicKeyShare"]
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        private_vss["privateVssShareProof"]["statementHash"],
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
