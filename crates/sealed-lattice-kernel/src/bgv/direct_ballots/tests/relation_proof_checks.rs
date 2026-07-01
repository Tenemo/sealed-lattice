use super::*;

#[test]
fn direct_ballot_shared_rns_relation_proof_verifies() {
    let fixture = direct_ballot_relation_proof_fixture();

    verify_direct_ballot_relation_proof(
        &fixture.setup_package,
        &fixture.evaluator_key,
        &fixture.encrypted_ballot,
        &fixture.proof_generation.proof_bytes,
    )
    .expect("proof verification");

    assert!(fixture.proof_generation.proof_size_bytes > 0);
    assert!(
        !fixture
            .proof_generation
            .relation_commitment_hash_hex
            .is_empty()
    );
    assert!(!fixture.proof_generation.challenge.is_empty());
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
        &fixture.evaluator_key,
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
    let single_bit_mutation_cases: [(&str, usize, &str); 4] = [
        (
            "randomizer response",
            direct_ballot_relation_response_offset(proof_bytes),
            "randomizer support check failed",
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
            &fixture.evaluator_key,
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
fn direct_ballot_relation_proof_rejects_linear_consistent_non_boolean_one_hot_witness() {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
            .expect("encrypted ballot");
    let mut one_hot_witnesses = one_hot_witnesses_for_scores(&encrypted_ballot.input.scores);
    one_hot_witnesses[0] = vec![0, 0, 0, 0, 0, 0, 0, 65536, 2, 0];
    encrypted_ballot.input.one_hot_witnesses = Some(one_hot_witnesses);
    let proof_randomness_seed_hex =
        direct_ballot_proof_randomness_seed(DIRECT_BALLOT_TEST_SETUP_SEED, &encrypted_ballot);
    let proof_generation = generate_direct_ballot_relation_proof(
        &setup_package,
        &evaluator_key,
        &encrypted_ballot,
        &proof_randomness_seed_hex,
    )
    .expect("proof generation");

    let error = verify_direct_ballot_relation_proof(
        &setup_package,
        &evaluator_key,
        &encrypted_ballot,
        &proof_generation.proof_bytes,
    )
    .expect_err("non-Boolean one-hot witness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("one-hot Booleanity option 0 support check failed")
    );
}

#[test]
fn direct_ballot_shared_rns_relation_proof_rejects_wrong_public_key() {
    let fixture = direct_ballot_relation_proof_fixture();
    let wrong_setup_package = setup_package_with_seed("direct-encrypted-ballot-wrong-seed");
    let wrong_evaluator_key = development_evaluator_key_from_passive_setup_package(
        &wrong_setup_package,
        "direct-encrypted-ballot-wrong-seed",
    )
    .expect("wrong evaluator key");

    let error = verify_direct_ballot_relation_proof(
        &wrong_setup_package,
        &wrong_evaluator_key,
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
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
            .expect("encrypted ballot");
    let last_limb_index = DATA_PRIMES.len() - 1;
    encrypted_ballot.ciphertext.components[0][last_limb_index][0] = add_mod(
        encrypted_ballot.ciphertext.components[0][last_limb_index][0],
        1,
        DATA_PRIMES[last_limb_index],
    )
    .expect("mutated residue");

    let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
        .expect_err("last limb mutation must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("RNS limb 16 c0 relation failed"));
}

#[test]
fn direct_ballot_all_limb_relation_rejects_different_plaintext_witness() {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
            .expect("encrypted ballot");
    encrypted_ballot.plaintext_coefficients[0] += 1;

    let error = validate_all_limb_encryption_relation(&evaluator_key, &encrypted_ballot)
        .expect_err("different plaintext witness must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains("RNS limb 0 c0 relation failed"));
}

#[test]
fn direct_ballot_support_rejects_out_of_range_randomizer() {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let mut encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
            .expect("encrypted ballot");
    encrypted_ballot.encryption_witness.randomizer_coefficients[0] = 2;

    let error = validate_encryption_witness_support(&encrypted_ballot.encryption_witness)
        .expect_err("out-of-range randomizer must reject");

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(error.message.contains(
        "direct encrypted ballot randomizer has a coefficient outside the expected support"
    ));
}

#[test]
fn direct_ballot_support_rejects_out_of_range_error_polynomials() {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        DIRECT_BALLOT_TEST_SETUP_SEED,
    )
    .expect("evaluator key");
    let encrypted_ballot =
        encrypt_direct_ballot(&setup_package, &evaluator_key, valid_ballot_input())
            .expect("encrypted ballot");

    let mut first_error_ballot = encrypted_ballot.clone();
    first_error_ballot
        .encryption_witness
        .error_zero_coefficients[0] = 3;
    let first_error = validate_encryption_witness_support(&first_error_ballot.encryption_witness)
        .expect_err("out-of-range first error coefficient must reject");

    assert_eq!(first_error.code, CanonicalErrorCode::InvalidFixture);
    assert!(first_error.message.contains(
        "direct encrypted ballot first error polynomial has a coefficient outside the expected support"
    ));

    let mut second_error_ballot = encrypted_ballot;
    second_error_ballot
        .encryption_witness
        .error_one_coefficients[0] = -3;
    let second_error = validate_encryption_witness_support(&second_error_ballot.encryption_witness)
        .expect_err("out-of-range second error coefficient must reject");

    assert_eq!(second_error.code, CanonicalErrorCode::InvalidFixture);
    assert!(second_error.message.contains(
        "direct encrypted ballot second error polynomial has a coefficient outside the expected support"
    ));
}
