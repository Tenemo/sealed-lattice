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
