use super::*;

fn assert_setup_intent_refused(package: &serde_json::Value, expected_reason_code: &str) {
    let result = verify_collective_bgv_setup_intent_for_test(package)
        .expect("setup-intent verification response");
    assert_eq!(result["isValid"], false, "unexpected result: {result}");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], expected_reason_code,
        "unexpected refusal: {result}"
    );
}

#[test]
fn foundation_setup_parameters_hash_is_byte_stable() {
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    assert_eq!(
        setup_parameters["setupParametersHash"]
            .as_str()
            .expect("setup parameters hash"),
        "7f9ebdddb630b12e5aa3bef13381d862eaa5f66b9309692b9239b67069308058dd59b95565860d5c31de77b3a93852d694545e9343f4fb3eef9f21860d35f4dc",
    );
}

#[test]
fn collective_setup_parameters_expose_operative_foundation_parameters() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_parameters_expose_operative_foundation_parameters",
    );
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");

    assert_eq!(setup_parameters["participantCount"], 10);
    assert_eq!(setup_parameters["qShare"]["objectType"], "QSharePrimeList");
    assert_eq!(
        setup_parameters["qShare"]["primes"]
            .as_array()
            .expect("Q_share primes")
            .len(),
        DATA_PRIMES.len()
    );
    assert_eq!(
        setup_parameters["evaluatorKeySchedule"]["objectType"],
        "EvaluatorKeySchedule"
    );
    assert!(
        !setup_parameters["evaluatorKeySchedule"]["relinearizationLevelSchedule"]
            .as_array()
            .expect("relinearization schedule")
            .is_empty()
    );
    assert!(
        !setup_parameters["evaluatorKeySchedule"]["requiredGaloisKeySchedule"]
            .as_array()
            .expect("required Galois schedule")
            .is_empty()
    );
    assert_eq!(
        setup_parameters["boundedDomainEvaluator"]["objectType"],
        "BoundedDomainEvaluatorParameters"
    );
    assert_eq!(
        setup_parameters["boundedDomainEvaluator"]["scoreDifferenceBound"],
        90
    );
    assert_eq!(
        setup_parameters["boundedDomainEvaluator"]["directComparisonOutputLevel"],
        6
    );
    assert!(setup_parameters["setupParametersHash"].as_str().is_some());
}

#[test]
fn collective_setup_intent_accepts_signed_canonical_registrations() {
    let package = collective_setup_intent_package();
    let result = verify_collective_bgv_setup_intent_for_test(&package)
        .expect("setup-intent verification response");

    assert_eq!(result["isValid"], true, "unexpected result: {result}");
}

#[test]
fn collective_setup_intent_refuses_missing_and_wrong_object_types() {
    let mut missing = collective_setup_intent_package();
    missing
        .as_object_mut()
        .expect("setup package")
        .remove("setupIntent");
    assert_setup_intent_refused(&missing, "setupObjectMissing");

    let mut wrong_wrapper_type = collective_setup_intent_package();
    wrong_wrapper_type["setupIntent"]["objectType"] = serde_json::json!("SetupIntent");
    assert_setup_intent_refused(&wrong_wrapper_type, "setupIntentTypeMismatch");

    let mut wrong_registration_type = collective_setup_intent_package();
    wrong_registration_type["setupIntent"]["trusteeRegistrations"][0]["objectType"] =
        serde_json::json!("TrusteeRegistration");
    assert_setup_intent_refused(
        &wrong_registration_type,
        "setupIntentTrusteeRegistrationTypeMismatch",
    );
}

#[test]
fn collective_setup_intent_refuses_duplicate_trustee_identities() {
    let mut duplicate = collective_setup_intent_package();
    duplicate["setupIntent"]["trusteeRegistrations"][1]["signatureEnvelope"]["signedRoot"]["signerIdentity"] =
        serde_json::json!("trustee-0");
    rebind_collective_setup_intent_registration_with_signature_seed(
        &mut duplicate,
        1,
        "trustee-1-setup-signing",
    );
    assert_setup_intent_refused(&duplicate, "setupIntentTrusteeIdentityDuplicate");
}

#[test]
fn collective_setup_intent_refuses_reused_signing_and_mailbox_keys() {
    let mut duplicate_signing_key = collective_setup_intent_package();
    rebind_collective_setup_intent_registration_with_signature_seed(
        &mut duplicate_signing_key,
        1,
        "trustee-0-setup-signing",
    );
    assert_setup_intent_refused(&duplicate_signing_key, "setupIntentSigningKeyDuplicate");

    let mut duplicate_mailbox_key = collective_setup_intent_package();
    let first_mailbox_public_key_hash = duplicate_mailbox_key["setupIntent"]
        ["trusteeRegistrations"][0]["privateVssMailboxPublicKeyHash"]
        .clone();
    duplicate_mailbox_key["setupIntent"]["trusteeRegistrations"][1]["privateVssMailboxPublicKeyHash"] =
        first_mailbox_public_key_hash;
    rebind_collective_setup_intent_registration(&mut duplicate_mailbox_key, 1);
    assert_setup_intent_refused(&duplicate_mailbox_key, "setupIntentMailboxKeyDuplicate");
}

#[test]
fn collective_setup_intent_refuses_a_rebound_wrong_roster() {
    let mut package = collective_setup_intent_package();
    let wrong_roster_hash = valid_hash('7');
    package["setupContext"]["rosterHash"] = serde_json::json!(wrong_roster_hash);
    rebind_collective_setup_intent_signatures(&mut package);

    assert_setup_intent_refused(&package, "setupRosterHashMismatch");
}

#[test]
fn collective_setup_intent_refuses_tampered_signature_bytes() {
    let mut package = collective_setup_intent_package();
    let signature_bytes =
        package["setupIntent"]["trusteeRegistrations"][0]["signatureEnvelope"]["signatureBytesHex"]
            .as_str()
            .expect("signature bytes")
            .to_string();
    let replacement_prefix = if signature_bytes.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let mut tampered_signature_bytes = signature_bytes;
    tampered_signature_bytes.replace_range(0..2, replacement_prefix);
    package["setupIntent"]["trusteeRegistrations"][0]["signatureEnvelope"]["signatureBytesHex"] =
        serde_json::json!(tampered_signature_bytes);

    assert_setup_intent_refused(&package, "InvalidSignature");
}

#[test]
fn collective_setup_verifier_binds_private_vss_envelopes_to_registered_mailbox_keys() {
    let mut package = collective_setup_intent_package();
    package["setupIntent"]["trusteeRegistrations"][0]["privateVssMailboxPublicKeyHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_intent_registration(&mut package, 0);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    assert_eq!(result["isValid"], false, "unexpected result: {result}");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "privateVssEncryptedEnvelopeBindingMismatch",
        "unexpected refusal: {result}"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_setup_context_tokens_first() {
    for (field_name, malformed_value) in [
        ("ceremonyId", "ceremony one"),
        ("setupEpoch", "setup-epoch-1\nfork"),
        (
            "setupEpoch",
            "setup-epoch-000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let mut package = collective_setup_intent_package();
        package["setupContext"][field_name] = serde_json::json!(malformed_value);

        let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
            .expect("verification response");
        assert_eq!(
            result["refusedObjects"][0]["reasonCode"],
            "setupContextTokenMalformed"
        );
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            format!("setupPackage.setupContext.{field_name}")
        );
    }
}

#[test]
fn collective_setup_verifier_refuses_bad_common_randomness() {
    let mut missing_reveal = collective_setup_intent_package();
    missing_reveal["commonRandomness"]["revealRecords"]
        .as_array_mut()
        .expect("reveal records")
        .pop();
    rebind_collective_setup_package_hash(&mut missing_reveal);
    let missing_reveal_result =
        verify_collective_bgv_setup_package(&missing_reveal, &serde_json::json!({}))
            .expect("verification response");
    assert_eq!(
        missing_reveal_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessRevealCountMismatch"
    );

    let mut wrong_seed = collective_setup_intent_package();
    wrong_seed["commonRandomness"]["publicMatrixSeedHash"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut wrong_seed);
    let wrong_seed_result =
        verify_collective_bgv_setup_package(&wrong_seed, &serde_json::json!({}))
            .expect("verification response");
    assert_eq!(
        wrong_seed_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessPublicMatrixSeedMismatch"
    );
}
