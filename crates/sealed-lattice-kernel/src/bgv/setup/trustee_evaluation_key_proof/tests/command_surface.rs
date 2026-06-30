use super::*;

#[test]
fn trustee_proof_commands_round_trip_and_reject_tampered_bytes() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "cdcdabab",
        &[round_one(2), rotation(3, 1)],
        SMALL_RING_DEGREE,
        Some(3),
    )
    .expect("development instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate command");
    assert_eq!(generated["sameSecretLinkageIncluded"], true);
    verify_generated_proof(&statement, &generated);

    let mut tampered_proof_bytes = generated_proof_bytes(&generated);
    let flip_position = tampered_proof_bytes.len() / 2;
    tampered_proof_bytes[flip_position] ^= 1;
    assert!(
        verify_proof_bytes(&statement, &tampered_proof_bytes).is_err(),
        "tampered proof bytes must reject"
    );
}

#[test]
fn trustee_proof_commands_reject_noncanonical_public_statement_material() {
    let (round_two_statement, round_two_witness) =
        generate_development_trustee_instance("feed0102", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("round-two instance");
    let mut component_request = statement_request_value(&round_two_statement);
    component_request["keys"][0]["componentBByDigit"][0][0][0] = serde_json::json!(DATA_PRIMES[0]);
    component_request["secretCoefficients"] =
        serde_json::json!(round_two_witness.secret_coefficients);
    component_request["errorCoefficientsByKey"] =
        serde_json::json!(round_two_witness.error_coefficients_by_key);
    component_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    component_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&component_request).is_err(),
        "out-of-range componentBByDigit values must reject before proving"
    );

    let mut aggregate_request = statement_request_value(&round_two_statement);
    aggregate_request["keys"][0]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!(DATA_PRIMES[0]);
    aggregate_request["secretCoefficients"] =
        serde_json::json!(round_two_witness.secret_coefficients);
    aggregate_request["errorCoefficientsByKey"] =
        serde_json::json!(round_two_witness.error_coefficients_by_key);
    aggregate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    aggregate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&aggregate_request).is_err(),
        "out-of-range aggregate statement values must reject before proving"
    );

    let (statement, witness) =
        generate_development_trustee_instance("feed0304", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round-one instance");
    let mut material_bytes =
        component_material_bytes_for_request_key(&statement.keys[0], SMALL_RING_DEGREE);
    let coefficient_offset = 8 + (4 * 8);
    material_bytes[coefficient_offset..coefficient_offset + 8]
        .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
    let mut material_request = statement_request_value(&statement);
    material_request["keys"][0]
        .as_object_mut()
        .expect("key object")
        .remove("componentBByDigit");
    material_request["keys"][0]["componentMaterialBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&material_bytes));
    material_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    material_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    material_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    material_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&material_request).is_err(),
        "out-of-range binary component material must reject before proving"
    );
}

#[test]
fn anchor_proof_commands_round_trip_with_family_label() {
    let (statement, witness) = generate_development_trustee_instance_with_linkage(
        "fafa0101",
        &[],
        SMALL_RING_DEGREE,
        Some(DATA_PRIMES.len()),
    )
    .expect("anchor instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate anchor command");
    assert_eq!(generated["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(generated["keyCount"], 0);

    verify_generated_proof(&statement, &generated);

    // A keyless request whose context carries the evaluation-key binding
    // labels must be refused: the family decides the expected label list.
    let mut mislabeled_request = statement_request_value(&statement);
    mislabeled_request["context"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::Value::Null;
    mislabeled_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    mislabeled_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    mislabeled_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    mislabeled_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    mislabeled_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&mislabeled_request).is_err(),
        "a keyless statement without the anchor binding root must be refused"
    );
}

#[test]
fn public_key_share_commands_round_trip_with_family_label() {
    let (statement, witness) =
        generate_development_public_key_share_instance("cdcd010201", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate public-key share command");
    assert_eq!(generated["proofFamily"], "public-key-share");
    assert_eq!(generated["keyCount"], 1);
    assert_eq!(generated["sameSecretLinkageIncluded"], true);

    verify_generated_proof(&statement, &generated);

    // A public-key share request whose context carries the wrong binding
    // labels (the anchor's) must be refused.
    let mut mislabeled = statement_request_value(&statement);
    mislabeled["context"]["sameSecretStatementRoot"] = serde_json::Value::Null;
    mislabeled["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    mislabeled["errorCoefficientsByKey"] = serde_json::json!(witness.error_coefficients_by_key);
    mislabeled["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    mislabeled["openingRandomnessByLimb"] = serde_json::json!(witness.opening_randomness_by_limb);
    mislabeled["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    mislabeled["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&mislabeled).is_err(),
        "a public-key share statement without its binding roots must be refused"
    );
}

#[test]
fn proof_command_binds_randomness_seed_to_nonce_and_statement() {
    let (statement, witness) =
        generate_development_public_key_share_instance("ab12cd34", SMALL_RING_DEGREE)
            .expect("public-key share instance");
    let mut generate_request = statement_request_value(&statement);
    generate_request["secretCoefficients"] = serde_json::json!(witness.secret_coefficients);
    generate_request["errorCoefficientsByKey"] =
        serde_json::json!(witness.error_coefficients_by_key);
    generate_request["negativeIndicatorCoefficients"] =
        serde_json::json!(witness.negative_indicator_coefficients);
    generate_request["openingRandomnessByLimb"] =
        serde_json::json!(witness.opening_randomness_by_limb);
    generate_request["proofRandomnessSeedHex"] = serde_json::json!(PROOF_RANDOMNESS_SEED);
    generate_request["proofRandomnessNonceHex"] = serde_json::json!(PROOF_RANDOMNESS_NONCE);

    let generated = super::generate_trustee_evaluation_key_proof_from_request(&generate_request)
        .expect("generate with nonce");

    let mut changed_nonce_request = generate_request.clone();
    changed_nonce_request["proofRandomnessNonceHex"] = serde_json::json!("11".repeat(64));
    let changed_nonce_generated =
        super::generate_trustee_evaluation_key_proof_from_request(&changed_nonce_request)
            .expect("generate with changed nonce");
    assert_ne!(
        generated["proofBytesHex"], changed_nonce_generated["proofBytesHex"],
        "the same seed and statement must not reuse proof masks when the nonce changes"
    );

    let mut short_seed_request = generate_request.clone();
    short_seed_request["proofRandomnessSeedHex"] = serde_json::json!("00".repeat(63));
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&short_seed_request).is_err(),
        "short proof randomness seed material must reject"
    );

    let mut missing_nonce_request = generate_request;
    missing_nonce_request
        .as_object_mut()
        .expect("request object")
        .remove("proofRandomnessNonceHex");
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&missing_nonce_request).is_err(),
        "proof generation without an explicit nonce must reject"
    );
}
