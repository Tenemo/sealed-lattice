use super::*;

#[test]
fn foundation_setup_parameters_hash_is_byte_stable() {
    // Byte-identity guard for the fixed n=10 foundation setup parameters. This
    // pin tracks the participant count, evaluator key schedule, bounded-domain
    // evaluator parameters, and BGV parameters. If those binding inputs
    // intentionally change, re-pin and treat stale proof corpora as invalid.
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    assert_eq!(
        setup_parameters["setupParametersHash"]
            .as_str()
            .expect("setup parameters hash"),
        "064c26fdfe51bdd6ea4ae1136475f64eb330b13e90692c2cbd1f34abacd28ecd89c19a70d3f9578b03e8c3d105e5e80de3f6a95703c39ac6a47b1485b011db26",
    );
}

#[test]
fn collective_setup_parameters_expose_operative_foundation_parameters() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_parameters_expose_operative_foundation_parameters",
    );
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");

    assert_eq!(setup_parameters["participantCount"], 10);
    assert_eq!(setup_parameters["qSetupComplete"], 10);
    assert_eq!(setup_parameters["qBallotRelease"], 10);
    assert_eq!(setup_parameters["qFinal"], 10);
    assert_eq!(setup_parameters["qDec"], 4);
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
    assert!(
        setup_parameters["evaluatorKeySchedule"]["requiredGaloisSetHash"]
            .as_str()
            .is_some()
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
    assert_eq!(
        setup_parameters["boundedDomainEvaluator"]["tiePolicy"],
        "higher-sum-first-then-lower-option-index"
    );
    assert_eq!(
        setup_parameters["phaseOrder"]
            .as_array()
            .expect("phase order")
            .len(),
        15
    );
    assert!(
        setup_parameters["phaseOrder"]
            .as_array()
            .expect("phase order")
            .iter()
            .any(|phase| phase == "trusteeEvaluationKeyProofs")
    );
    assert!(setup_parameters["setupParametersHash"].as_str().is_some());
    assert!(setup_parameters["phaseOrderHash"].as_str().is_some());
}

#[test]
fn collective_setup_verifier_refuses_passive_setup_packages() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_passive_setup_packages");
    let package = setup_package();
    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "outsideCollectiveBgvSetupParameters"
    );
}

#[test]
fn collective_setup_verifier_refuses_a_missing_required_phase() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_a_missing_required_phase");
    let mut package = collective_setup_phase_package();
    package
        .as_object_mut()
        .expect("package object")
        .remove("phaseTranscript");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"],
        serde_json::json!([{
            "reasonCode": "setupObjectMissing",
            "message": "A required setup object is missing.",
            "objectPath": "setupPackage.phaseTranscript",
        }])
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_setup_context_tokens_before_missing_prerequisites() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_setup_context_tokens_before_missing_prerequisites",
    );

    for (field_name, malformed_value) in [
        ("ceremonyId", "ceremony one"),
        ("setupEpoch", "setup-epoch-1\nfork"),
        (
            "setupEpoch",
            "setup-epoch-000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let mut package = collective_setup_phase_package();
        package["setupContext"][field_name] = serde_json::json!(malformed_value);
        package
            .as_object_mut()
            .expect("package object")
            .remove("phaseTranscript");
        rebind_collective_setup_package_hash(&mut package);
        package
            .as_object_mut()
            .expect("package object")
            .remove("setupPackageHash");

        let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
            .expect("verification response");

        assert_eq!(result["isValid"], false);
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
fn collective_setup_verifier_detects_phase_forks_and_wrong_order() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_detects_phase_forks_and_wrong_order");
    let mut forked_package = collective_setup_phase_package();
    let first_phase = forked_package["phaseTranscript"][0].clone();
    let mut forked_phase = first_phase.clone();
    forked_phase["phaseRoot"] = serde_json::json!(valid_hash('2'));
    forked_package["phaseTranscript"] = serde_json::json!([first_phase, forked_phase]);
    rebind_collective_setup_package_hash(&mut forked_package);
    let forked_result =
        verify_collective_bgv_setup_package(&forked_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(forked_result["isValid"], false);
    assert_eq!(
        forked_result["refusedObjects"][0]["reasonCode"],
        "phaseForkDetected"
    );

    let mut wrong_order_package = collective_setup_phase_package();
    wrong_order_package["phaseTranscript"] = serde_json::json!([
        { "phaseId": "setupIntent", "phaseRoot": valid_hash('3') }
    ]);
    rebind_collective_setup_package_hash(&mut wrong_order_package);
    let wrong_order_result =
        verify_collective_bgv_setup_package(&wrong_order_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_order_result["isValid"], false);
    assert_eq!(
        wrong_order_result["refusedObjects"][0]["reasonCode"],
        "phaseOrderMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_stale_phase_epoch_and_bad_phase_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_stale_phase_epoch_and_bad_phase_roots",
    );
    let mut stale_epoch_package = collective_setup_phase_package();
    stale_epoch_package["phaseTranscript"][1]["setupEpoch"] = serde_json::json!("old-epoch");
    rebind_collective_setup_package_hash(&mut stale_epoch_package);

    let stale_epoch_result =
        verify_collective_bgv_setup_package(&stale_epoch_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(stale_epoch_result["isValid"], false);
    assert_eq!(
        stale_epoch_result["refusedObjects"][0]["reasonCode"],
        "phaseContextMismatch"
    );

    let mut bad_root_package = collective_setup_phase_package();
    bad_root_package["phaseTranscript"][1]["phaseRoot"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut bad_root_package);

    let bad_root_result =
        verify_collective_bgv_setup_package(&bad_root_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(bad_root_result["isValid"], false);
    assert_eq!(
        bad_root_result["refusedObjects"][0]["reasonCode"],
        "phaseRootMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_phase_signature_after_rebinding() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_phase_signature_after_rebinding",
    );
    let mut package = collective_setup_phase_package();
    let participant = &mut package["phaseTranscript"][0]["participantPhaseObjects"][0];
    let signature_envelope = participant
        .get_mut("signatureEnvelope")
        .expect("signature envelope");
    let signature_bytes_hex = signature_envelope["signatureBytesHex"]
        .as_str()
        .expect("signature bytes")
        .to_string();
    let replacement_prefix = if signature_bytes_hex.starts_with("00") {
        "01"
    } else {
        "00"
    };
    let mut tampered_signature_bytes_hex = signature_bytes_hex;
    tampered_signature_bytes_hex.replace_range(0..2, replacement_prefix);
    signature_envelope["signatureBytesHex"] = serde_json::json!(tampered_signature_bytes_hex);
    rebind_collective_phase_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    assert_eq!(result["isValid"], false);
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}

#[test]
fn collective_setup_verifier_refuses_bad_common_randomness() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_bad_common_randomness");
    let mut missing_reveal_package = collective_setup_phase_package();
    missing_reveal_package["commonRandomness"]["revealRecords"]
        .as_array_mut()
        .expect("reveal records")
        .pop();
    rebind_collective_setup_package_hash(&mut missing_reveal_package);

    let missing_reveal_result =
        verify_collective_bgv_setup_package(&missing_reveal_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(missing_reveal_result["isValid"], false);
    assert_eq!(
        missing_reveal_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessRevealCountMismatch"
    );

    let mut wrong_seed_package = collective_setup_phase_package();
    wrong_seed_package["commonRandomness"]["publicMatrixSeedHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut wrong_seed_package);

    let wrong_seed_result =
        verify_collective_bgv_setup_package(&wrong_seed_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_seed_result["isValid"], false);
    assert_eq!(
        wrong_seed_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessPublicMatrixSeedMismatch"
    );

    let mut wrong_derivation_package = collective_setup_phase_package();
    wrong_derivation_package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut wrong_derivation_package);

    let wrong_derivation_result =
        verify_collective_bgv_setup_package(&wrong_derivation_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_derivation_result["isValid"], false);
    assert_eq!(
        wrong_derivation_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );
}
