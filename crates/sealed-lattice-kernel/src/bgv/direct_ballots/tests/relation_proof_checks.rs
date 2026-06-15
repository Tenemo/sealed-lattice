use super::*;

#[test]
fn direct_ballot_shared_rns_relation_proof_verifies() {
    let fixture = direct_ballot_relation_proof_fixture();

    validate_direct_ballot_public_preflight(&fixture.public_key, &fixture.encrypted_ballot)
        .expect("public-key preflight");

    let proof_verification = verify_direct_ballot_relation_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.proof_bytes,
    )
    .expect("proof verification");

    assert_eq!(
        proof_verification.relation_commitment_hash_hex,
        fixture.proof_generation.relation_commitment_hash_hex
    );
    assert_eq!(
        proof_verification.challenge,
        fixture.proof_generation.challenge
    );
    assert!(fixture.proof_generation.proof_size_bytes > 0);
}

#[test]
fn direct_ballot_public_preflight_rejects_ciphertext_from_different_public_key() {
    let setup_package = setup_package();
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
    let wrong_public_key =
        public_bgv_key_from_passive_setup_package(&wrong_setup_package).expect("wrong public key");
    let encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &wrong_public_key, valid_ballot_input())
            .expect("encrypted ballot");

    let error = validate_direct_ballot_public_preflight(&public_key, &encrypted_ballot)
        .expect_err("ciphertext encrypted under a different public key must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("RNS limb 0 c0 relation failed"));
}

#[test]
fn direct_ballot_shared_rns_relation_proof_rejects_last_limb_ciphertext_mutation() {
    let fixture = direct_ballot_relation_proof_fixture();
    let mut encrypted_ballot = fixture.encrypted_ballot.clone();
    let last_limb_index = DATA_PRIMES.len() - 1;
    encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
        encrypted_ballot.ciphertext.components[0][last_limb_index][0],
        1,
        DATA_PRIMES[last_limb_index],
    )
    .expect("mutated residue");

    let error = verify_direct_ballot_relation_proof(
        &fixture.setup_package,
        &fixture.public_key,
        &encrypted_ballot,
        &fixture.proof_generation.proof_bytes,
    )
    .expect_err("mutated last limb must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error.message.contains("not bound to this statement")
            || error.message.contains("limb 16 c0 response")
    );
}

#[test]
fn direct_ballot_shared_rns_relation_proof_rejects_single_bit_proof_mutations() {
    let fixture = direct_ballot_relation_proof_fixture();
    let proof_bytes = &fixture.proof_generation.proof_bytes;
    let score_response_offset = direct_ballot_score_response_offset(proof_bytes);

    // Each case flips a single bit at a distinct structural offset in the
    // serialized relation proof and asserts the verifier rejects with that
    // offset's specific reason. Folding the offsets into one table keeps every
    // offset-and-message assertion while dropping four copies of the identical
    // clone-mutate-verify body.
    let single_bit_mutation_cases: [(&str, usize, &str); 5] = [
        (
            "randomizer response",
            direct_ballot_relation_response_offset(proof_bytes),
            "randomizer projected support check failed",
        ),
        (
            "score response",
            score_response_offset,
            "direct ballot score proof option 0",
        ),
        (
            "one-hot response",
            score_response_offset
                + DIRECT_BALLOT_OPTION_COUNT * direct_ballot_response_coefficient_bytes(),
            "direct ballot score proof option 0",
        ),
        (
            "projected BGV no-wrap carry response",
            direct_ballot_projected_bgv_no_wrap_response_offset(proof_bytes),
            "direct ballot projected BGV no-wrap relation limb 0 component zero projection 0 failed",
        ),
        (
            "relation commitment",
            direct_ballot_relation_commitment_offset(proof_bytes),
            "challenge does not match its commitment",
        ),
    ];

    for (case_label, mutation_offset, expected_message_fragment) in single_bit_mutation_cases {
        let mut mutated_proof_bytes = fixture.proof_generation.proof_bytes.clone();
        mutated_proof_bytes[mutation_offset] ^= 1;

        let error = match verify_direct_ballot_relation_proof(
            &fixture.setup_package,
            &fixture.public_key,
            &fixture.encrypted_ballot,
            &mutated_proof_bytes,
        ) {
            Ok(_) => panic!("{case_label}: mutated proof must reject"),
            Err(error) => error,
        };

        assert_eq!(
            error.code,
            CanonicalErrorCode::InvalidFixture,
            "{case_label}: unexpected rejection code"
        );
        assert!(
            error.message.contains(expected_message_fragment),
            "{case_label}: unexpected rejection message: {}",
            error.message
        );
    }
}

#[test]
fn direct_ballot_relation_proof_generation_rejects_linear_consistent_non_boolean_one_hot_witness() {
    let setup_package = setup_package();
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
            .expect("encrypted ballot");
    let mut one_hot_witnesses = one_hot_witnesses_for_scores(&encrypted_ballot.input.scores);
    one_hot_witnesses[0] = vec![0, 0, 0, 0, 0, 0, 0, 65536, 2, 0];
    encrypted_ballot.input.one_hot_witnesses = Some(one_hot_witnesses);
    let proof_randomness_seed_hex =
        direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
    let error = match generate_direct_ballot_relation_proof(
        &setup_package,
        &public_key,
        &encrypted_ballot,
        &proof_randomness_seed_hex,
    ) {
        Ok(_) => panic!("non-Boolean one-hot witness must reject during proof generation"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("committed one-hot Booleanity row failed at option 0 bucket 7")
    );
}

#[test]
fn direct_ballot_shared_rns_relation_proof_rejects_wrong_public_key() {
    let fixture = direct_ballot_relation_proof_fixture();
    let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
    let wrong_public_key =
        public_bgv_key_from_passive_setup_package(&wrong_setup_package).expect("wrong public key");

    let error = verify_direct_ballot_relation_proof(
        &wrong_setup_package,
        &wrong_public_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.proof_bytes,
    )
    .expect_err("wrong public key must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("not bound to this statement"));
}

#[test]
fn direct_ballot_all_limb_relation_rejects_last_limb_mutation() {
    let setup_package = setup_package();
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
            .expect("encrypted ballot");
    let last_limb_index = DATA_PRIMES.len() - 1;
    encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
        encrypted_ballot.ciphertext.components[0][last_limb_index][0],
        1,
        DATA_PRIMES[last_limb_index],
    )
    .expect("mutated residue");

    let error = validate_all_limb_encryption_relation(&public_key, &encrypted_ballot)
        .expect_err("last limb mutation must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("RNS limb 16 c0 relation failed"));
}

#[test]
fn direct_ballot_all_limb_relation_rejects_different_plaintext_witness() {
    let setup_package = setup_package();
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
            .expect("encrypted ballot");
    encrypted_ballot.plaintext_coefficients[0] += 1;

    let error = validate_all_limb_encryption_relation(&public_key, &encrypted_ballot)
        .expect_err("different plaintext witness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("RNS limb 0 c0 relation failed"));
}

#[test]
fn direct_ballot_support_rejects_out_of_range_randomizer() {
    let setup_package = setup_package();
    let public_key = public_bgv_key_from_passive_setup_package(&setup_package).expect("public key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &public_key, valid_ballot_input())
            .expect("encrypted ballot");
    encrypted_ballot.encryption_witness.randomizer_coefficients[0] = 2;

    let error = validate_encryption_witness_support(&encrypted_ballot.encryption_witness)
        .expect_err("out-of-range randomizer must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains(
        "direct encrypted ballot randomizer has a coefficient outside the expected support"
    ));
}
