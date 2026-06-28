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
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["sameSecretLinkageIncluded"], true);
    let proof_bytes_hex = generated["proofBytesHex"].as_str().expect("proof bytes");

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = serde_json::json!(proof_bytes_hex);
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["statementHash"], generated["statementHash"]);

    let mut tampered_request = statement_request_value(&statement);
    let mut tampered_hex = proof_bytes_hex.to_string();
    let flip_position = tampered_hex.len() / 2;
    let original = tampered_hex.as_bytes()[flip_position];
    let replacement = if original == b'0' { '1' } else { '0' };
    tampered_hex.replace_range(flip_position..flip_position + 1, &replacement.to_string());
    tampered_request["proofBytesHex"] = serde_json::json!(tampered_hex);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&tampered_request).is_err(),
        "tampered proof bytes must reject"
    );
}

#[test]
fn trustee_proof_commands_reject_noncanonical_public_statement_material() {
    let (round_two_statement, round_two_witness) =
        generate_development_trustee_instance("feed0102", &[round_two(2)], SMALL_RING_DEGREE)
            .expect("round-two instance");
    let round_two_proof = prove_evaluation_key_share(
        &round_two_statement,
        &round_two_witness,
        PROOF_RANDOMNESS_SEED,
    )
    .expect("round-two proof");
    let round_two_proof_bytes = encode_trustee_evaluation_key_proof(&round_two_proof);

    let mut component_request = statement_request_value(&round_two_statement);
    component_request["proofBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&round_two_proof_bytes));
    component_request["keys"][0]["componentBByDigit"][0][0][0] = serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&component_request).is_err(),
        "out-of-range componentBByDigit values must reject before verification"
    );

    let mut aggregate_request = statement_request_value(&round_two_statement);
    aggregate_request["proofBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&round_two_proof_bytes));
    aggregate_request["keys"][0]["roundOneAggregateDiagonal"][0][0] =
        serde_json::json!(DATA_PRIMES[0]);
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&aggregate_request).is_err(),
        "out-of-range aggregate statement values must reject before verification"
    );

    let (statement, witness) =
        generate_development_trustee_instance("feed0304", &[round_one(2)], SMALL_RING_DEGREE)
            .expect("round-one instance");
    let proof =
        prove_evaluation_key_share(&statement, &witness, PROOF_RANDOMNESS_SEED).expect("proof");
    let mut material_bytes =
        component_material_bytes_for_request_key(&statement.keys[0], SMALL_RING_DEGREE);
    let coefficient_offset = 8 + (4 * 8);
    material_bytes[coefficient_offset..coefficient_offset + 8]
        .copy_from_slice(&DATA_PRIMES[0].to_le_bytes());
    let mut material_request = statement_request_value(&statement);
    material_request["proofBytesHex"] = serde_json::json!(crate::hashing::to_hex(
        &encode_trustee_evaluation_key_proof(&proof)
    ));
    material_request["keys"][0]
        .as_object_mut()
        .expect("key object")
        .remove("componentBByDigit");
    material_request["keys"][0]["componentMaterialBytesHex"] =
        serde_json::json!(crate::hashing::to_hex(&material_bytes));
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&material_request).is_err(),
        "out-of-range binary component material must reject before verification"
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
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(generated["keyCount"], 0);

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify anchor command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(verified["statementHash"], generated["statementHash"]);

    // A keyless request whose context carries the evaluation-key binding
    // labels must be refused: the family decides the expected label list.
    let mut mislabeled_request = statement_request_value(&statement);
    mislabeled_request["context"]["vssCoefficientCommitmentMaterialRoot"] = serde_json::Value::Null;
    mislabeled_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&mislabeled_request).is_err(),
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
    assert_eq!(generated["ok"], true);
    assert_eq!(generated["proofFamily"], "public-key-share");
    assert_eq!(generated["keyCount"], 1);
    assert_eq!(generated["sameSecretLinkageIncluded"], true);
    let expected_accounting_hash =
        super::accounting::succinct_public_key_share_accounting_hash().expect("accounting hash");
    assert_eq!(generated["proofAccountingHash"], expected_accounting_hash);

    let mut verify_request = statement_request_value(&statement);
    verify_request["proofBytesHex"] = generated["proofBytesHex"].clone();
    let verified = super::verify_trustee_evaluation_key_proof_from_request(&verify_request)
        .expect("verify public-key share command");
    assert_eq!(verified["ok"], true);
    assert_eq!(verified["proofFamily"], "public-key-share");
    assert_eq!(verified["statementHash"], generated["statementHash"]);
    assert_eq!(
        verified["proofAccounting"]["proofFamily"],
        "public-key-share"
    );

    // A public-key share request whose context carries the wrong binding
    // labels (the anchor's) must be refused.
    let mut mislabeled = statement_request_value(&statement);
    mislabeled["context"]["sameSecretStatementRoot"] = serde_json::Value::Null;
    mislabeled["proofBytesHex"] = generated["proofBytesHex"].clone();
    assert!(
        super::verify_trustee_evaluation_key_proof_from_request(&mislabeled).is_err(),
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

    let mut uppercase_seed_request = generate_request.clone();
    uppercase_seed_request["proofRandomnessSeedHex"] =
        serde_json::json!(PROOF_RANDOMNESS_SEED.to_ascii_uppercase());
    assert!(
        super::generate_trustee_evaluation_key_proof_from_request(&uppercase_seed_request).is_err(),
        "uppercase proof randomness seed material must reject"
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
