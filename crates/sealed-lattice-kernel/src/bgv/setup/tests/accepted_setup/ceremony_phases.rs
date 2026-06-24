use super::*;

#[test]
fn first_closure_setup_parameters_hash_is_byte_stable() {
    // Byte-identity guard for the current n=10 closure setup parameters. This
    // pin tracks the full n=10 binding, including the inlined sub-configuration
    // values, the proof-accounting sub-hashes, and the BGV parameters; if those
    // binding inputs intentionally change, re-pin to the new n=10 value and
    // treat stale proof corpora as invalid.
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");
    assert_eq!(
        setup_parameters["setupParametersHash"]
            .as_str()
            .expect("setup parameters hash"),
        "0e07eb07c3ca6afd66b83951397b6580857ceaea6c395ae45f557022687c5ba7be88febf3710272442e5a6bcf67d89e54ab8327c106dceee7190137b4395e12a",
    );
}

#[test]
fn collective_setup_parameters_expose_first_closure_state_machine() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_parameters_expose_first_closure_state_machine",
    );
    let setup_parameters = describe_collective_bgv_setup_parameters().expect("setup parameters");

    assert_eq!(setup_parameters["objectType"], "SetupPackage");
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
        setup_parameters["carryAwareVssShareRelation"]["objectType"],
        "CarryAwareVssShareRelation"
    );
    assert_eq!(
        setup_parameters["commitment"]["objectType"],
        "BdlopCommitment"
    );
    assert_eq!(
        setup_parameters["commitment"]["assumptions"]["hiding"],
        "Module-LWE over the selected commitment modulus limbs with short centered-ternary openings"
    );
    assert_eq!(
        setup_parameters["commitment"]["assumptions"]["binding"],
        "Module-SIS over the selected commitment modulus limbs for the published BDLOP matrix"
    );
    assert_eq!(
        setup_parameters["commitment"]["assumptions"]["requiredCertificates"],
        serde_json::json!([
            "SetupCommitmentSecurityCertificate",
            "SetupProofAccountingCertificate"
        ])
    );
    assert_eq!(
        setup_parameters["publicVssCommitmentMaterialSize"]["objectType"],
        "PublicVssCommitmentMaterialSize"
    );
    assert_eq!(
        setup_parameters["publicVssCommitmentMaterialSize"]["ringDegree"],
        POLYNOMIAL_DEGREE
    );
    assert_eq!(
        setup_parameters["publicVssCommitmentMaterialSize"]["fullMaterialCoefficientBytes"],
        serde_json::json!(1_604_321_280_u64)
    );
    assert_eq!(
        setup_parameters["publicVssCommitmentMaterialSize"]["fullMaterialCoefficientMebibytes"],
        1_530
    );
    assert_eq!(setup_parameters["setupProof"]["objectType"], "SetupProof");
    let setup_proof_families = setup_parameters["setupProof"]["proofFamilies"]
        .as_array()
        .expect("setup proof family parameters");
    assert_eq!(setup_proof_families.len(), 4);
    for expected_family in [
        "same-secret-linkage-anchor",
        "public-key-share",
        "vss-opening-carry",
        "trustee-evaluation-key",
    ] {
        assert!(
            setup_proof_families.iter().any(|family_parameters| {
                family_parameters["proofFamily"]
                    .as_str()
                    .is_some_and(|proof_family| proof_family == expected_family)
            }),
            "setup proof parameters must list {expected_family}"
        );
    }
    assert_eq!(
        setup_parameters["setupTransport"]["objectType"],
        "SetupTransport"
    );
    assert_eq!(
        setup_parameters["setupTransport"]["chunkSizeBytes"],
        1_048_576
    );
    assert_eq!(
        setup_parameters["setupTransport"]["storageQuotaBytes"],
        2_147_483_648_u64
    );
    assert_eq!(
        setup_parameters["setupTransport"]["streamVerificationOrder"],
        "ascending-chunk-index"
    );
    assert_eq!(
        setup_parameters["setupTransport"]["lazyLoadingPolicy"],
        "root-addressed-large-object-loading"
    );
    assert_eq!(
        setup_parameters["evaluatorKeySchedule"]["objectType"],
        "EvaluatorKeySchedule"
    );
    assert_eq!(
        setup_parameters["evaluatorKeySchedule"]["genericKeySwitchPolicy"],
        "refused-unless-explicitly-required"
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
        setup_parameters["verifierStatuses"],
        serde_json::json!([
            "accepted",
            "pending",
            "refused",
            "aborted",
            "forkDetected",
            "outsideAcceptedParameters"
        ])
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
            .any(|phase| phase["phaseId"] == "trusteeEvaluationKeyProofs")
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

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "outsideAcceptedParameters");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "outsideCollectiveBgvSetupParameters"
    );
}

#[test]
fn collective_setup_verifier_reports_missing_phase_as_pending() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_reports_missing_phase_as_pending");
    let mut package = minimal_collective_setup_package();
    package
        .as_object_mut()
        .expect("package object")
        .remove("phaseTranscript");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "pending");
    assert_eq!(result["currentPhase"], "rosterFreeze");
    assert_eq!(
        result["missingObjects"],
        serde_json::json!(["phaseTranscript"])
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_setup_context_tokens_before_later_pending() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_setup_context_tokens_before_later_pending",
    );

    for (field_name, malformed_value) in [
        ("ceremonyId", "ceremony one"),
        ("setupEpoch", "setup-epoch-1\nfork"),
        (
            "setupEpoch",
            "setup-epoch-000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000",
        ),
    ] {
        let mut package = minimal_collective_setup_package();
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

        assert_eq!(result["verifierStatus"], "refused");
        assert_eq!(
            result["refusedObjects"][0]["reasonCode"],
            "setupContextTokenMalformed"
        );
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            format!("setupPackage.setupContext.{field_name}")
        );
        assert_eq!(result["missingObjects"], serde_json::json!([]));
        assert!(
            result.get("acceptedSetupHandoff").is_none(),
            "malformed setup context packages must not return an accepted setup handoff"
        );
    }
}

#[test]
fn collective_setup_verifier_detects_phase_forks_and_wrong_order() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_detects_phase_forks_and_wrong_order");
    let mut forked_package = minimal_collective_setup_package();
    let first_phase = forked_package["phaseTranscript"][0].clone();
    let mut forked_phase = first_phase.clone();
    forked_phase["participantPhaseObjects"][0]["signatureEnvelopeHash"] =
        serde_json::json!(valid_hash('2'));
    forked_package["phaseTranscript"] = serde_json::json!([first_phase, forked_phase]);
    rebind_collective_setup_package_hash(&mut forked_package);
    let forked_result =
        verify_collective_bgv_setup_package(&forked_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(forked_result["verifierStatus"], "forkDetected");
    assert_eq!(
        forked_result["refusedObjects"][0]["reasonCode"],
        "phaseForkDetected"
    );

    let mut wrong_order_package = minimal_collective_setup_package();
    wrong_order_package["phaseTranscript"] = serde_json::json!([
        { "phaseId": "setupIntent", "phaseNumber": 2, "phaseRoot": valid_hash('3') }
    ]);
    rebind_collective_setup_package_hash(&mut wrong_order_package);
    let wrong_order_result =
        verify_collective_bgv_setup_package(&wrong_order_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_order_result["verifierStatus"], "refused");
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
    let mut stale_epoch_package = minimal_collective_setup_package();
    stale_epoch_package["phaseTranscript"][1]["setupEpoch"] = serde_json::json!("old-epoch");
    rebind_collective_setup_package_hash(&mut stale_epoch_package);

    let stale_epoch_result =
        verify_collective_bgv_setup_package(&stale_epoch_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(stale_epoch_result["verifierStatus"], "refused");
    assert_eq!(
        stale_epoch_result["refusedObjects"][0]["reasonCode"],
        "phaseContextMismatch"
    );

    let mut bad_root_package = minimal_collective_setup_package();
    bad_root_package["phaseTranscript"][1]["phaseRoot"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut bad_root_package);

    let bad_root_result =
        verify_collective_bgv_setup_package(&bad_root_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(bad_root_result["verifierStatus"], "refused");
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
    let mut package = minimal_collective_setup_package();
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
    let signature_envelope_hash = derive_protocol_hash(
        "ProtocolSignatureEnvelopeHash",
        &serde_json::json!({
            "profile": signature_envelope["profile"],
            "publicKeyBytesHex": signature_envelope["publicKeyBytesHex"],
            "publicKeyHash": signature_envelope["publicKeyHash"],
            "signatureBytesHex": signature_envelope["signatureBytesHex"],
            "signedRoot": signature_envelope["signedRoot"],
        }),
    )
    .expect("signature envelope hash");
    signature_envelope["signatureHash"] = serde_json::json!(signature_envelope_hash.clone());
    participant["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_phase_roots(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
        .expect("verification response");
    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}

#[test]
fn collective_setup_verifier_refuses_bad_common_randomness() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_bad_common_randomness");
    let mut missing_reveal_package = minimal_collective_setup_package();
    missing_reveal_package["commonRandomness"]["revealRecords"]
        .as_array_mut()
        .expect("reveal records")
        .pop();
    rebind_collective_setup_package_hash(&mut missing_reveal_package);

    let missing_reveal_result =
        verify_collective_bgv_setup_package(&missing_reveal_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(missing_reveal_result["verifierStatus"], "refused");
    assert_eq!(
        missing_reveal_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessRevealCountMismatch"
    );

    let mut wrong_seed_package = minimal_collective_setup_package();
    wrong_seed_package["commonRandomness"]["publicMatrixSeedHash"] =
        serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut wrong_seed_package);

    let wrong_seed_result =
        verify_collective_bgv_setup_package(&wrong_seed_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_seed_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_seed_result["refusedObjects"][0]["reasonCode"],
        "commonRandomnessPublicMatrixSeedMismatch"
    );

    let mut wrong_derivation_package = minimal_collective_setup_package();
    wrong_derivation_package["commonRandomness"]["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"] =
        serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut wrong_derivation_package);

    let wrong_derivation_result =
        verify_collective_bgv_setup_package(&wrong_derivation_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_derivation_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_derivation_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );

    let mut wrong_matrix_package = minimal_collective_setup_package();
    wrong_matrix_package["commonRandomness"]["publicDerivations"]["publicMatrices"]["commitmentMatrix"]
        ["sampledEntries"][0]["entryDerivationHash"] = serde_json::json!(valid_hash('3'));
    rebind_collective_setup_package_hash(&mut wrong_matrix_package);

    let wrong_matrix_result =
        verify_collective_bgv_setup_package(&wrong_matrix_package, &serde_json::json!({}))
            .expect("verification response");

    assert_eq!(wrong_matrix_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_matrix_result["refusedObjects"][0]["reasonCode"],
        "setupPublicDerivationsMismatch"
    );
}
