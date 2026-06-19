use super::*;
use crate::bgv::direct_ballots::{
    aggregate_direct_encrypted_ballot_packages, create_direct_encrypted_ballot_packages,
    verify_direct_encrypted_ballot_package,
};

#[test]
fn collective_setup_verifier_refuses_forbidden_accepted_path_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_forbidden_accepted_path_material",
    );
    let mut seeded_package = minimal_collective_setup_package();
    seeded_package["setupSeed"] = serde_json::json!("externally-supplied-seed");
    rebind_collective_setup_package_hash(&mut seeded_package);

    let seeded_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": seeded_package,
    }))
    .expect("verification response");

    assert_eq!(seeded_result["verifierStatus"], "refused");
    assert_eq!(
        seeded_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );

    let mut externally_supplied_threshold_package = minimal_collective_setup_package();
    externally_supplied_threshold_package["externallySuppliedThresholdShareCommitmentMaterial"] =
        serde_json::json!({ "root": valid_hash('5') });
    rebind_collective_setup_package_hash(&mut externally_supplied_threshold_package);

    let externally_supplied_threshold_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": externally_supplied_threshold_package,
        }))
        .expect("verification response");

    assert_eq!(
        externally_supplied_threshold_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        externally_supplied_threshold_result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );
}

#[test]
fn collective_setup_verifier_refuses_proof_randomness_metadata_with_rebound_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_proof_randomness_metadata_with_rebound_roots",
    );

    for forbidden_field_name in [
        "proofGeneration",
        "proofRandomness",
        "proofRandomnessSource",
        "proofRandomnessSeedHex",
        "proofRandomnessNonceHex",
    ] {
        let mut package = minimal_collective_setup_package();
        package[forbidden_field_name] = forbidden_proof_randomness_metadata(forbidden_field_name);
        rebind_collective_setup_package_hash(&mut package);
        assert_refuses_forbidden_accepted_path_field(&package, forbidden_field_name);
    }

    for forbidden_field_name in [
        "proofRandomnessSource",
        "proofRandomnessSeedHex",
        "proofRandomnessNonceHex",
    ] {
        for proof_set_field_name in [
            "sameSecretProofs",
            "publicKeyShareSuccinctProofs",
            "trusteeEvaluationKeyProofs",
        ] {
            let mut package = minimal_collective_setup_package();
            package[proof_set_field_name] = serde_json::json!({
                "objectType": "FixtureTerminalProofSet",
                "objectVersion": 1,
                "proofRecords": [{
                    "objectType": "FixtureTerminalProofRecord",
                    "objectVersion": 1,
                    forbidden_field_name: forbidden_proof_randomness_metadata(forbidden_field_name),
                }],
            });
            rebind_collective_setup_package_hash(&mut package);
            assert_refuses_forbidden_accepted_path_field(&package, forbidden_field_name);
        }
    }
}

fn forbidden_proof_randomness_metadata(field_name: &str) -> serde_json::Value {
    match field_name {
        "proofGeneration" => serde_json::json!({
            "source": "development-deterministic-fixture",
            "proofRandomnessSeedHex": valid_hash('7'),
        }),
        "proofRandomness" => serde_json::json!({
            "source": "development-deterministic-fixture",
            "seedBytes": 64,
            "retention": "not-terminal-evidence",
        }),
        "proofRandomnessSource" => serde_json::json!("development-deterministic-fixture"),
        "proofRandomnessSeedHex" | "proofRandomnessNonceHex" => serde_json::json!(valid_hash('8')),
        _ => panic!("unsupported forbidden proof randomness field {field_name}"),
    }
}

fn assert_refuses_forbidden_accepted_path_field(
    package: &serde_json::Value,
    forbidden_field_name: &str,
) {
    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "acceptedPathForbiddenField"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains(forbidden_field_name)
    );
    assert!(
        result.get("acceptedSetupHandoff").is_none() || result["acceptedSetupHandoff"].is_null(),
        "refused proof-randomness metadata must not return an accepted setup handoff"
    );
}

#[test]
fn collective_setup_verifier_refuses_generic_key_switch_material_by_default() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_generic_key_switch_material_by_default",
    );
    let mut package = minimal_collective_setup_package();
    package["genericKeySwitchKeys"] = serde_json::json!({ "keyRoot": valid_hash('4') });
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "genericKeySwitchOutsideProfile"
    );
}

#[test]
fn collective_setup_verifier_refuses_premature_target_decryption_readiness_artifacts() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_premature_target_decryption_readiness_artifacts",
    );

    for forbidden_field_name in [
        "targetDecryptionStatus",
        "targetDecryptionReadiness",
        "targetDecryptionCertificate",
        "targetDecryptionCertificateHash",
        "targetDecryptionClosure",
        "targetDecryptionShareProofs",
        "targetDecryptionShares",
        "targetPartDecRecords",
        "targetC1C4Certificate",
    ] {
        let mut package = minimal_collective_setup_package();
        package[forbidden_field_name] = premature_target_decryption_artifact(forbidden_field_name);
        rebind_collective_setup_package_hash(&mut package);
        assert_refuses_forbidden_accepted_path_field(&package, forbidden_field_name);
    }

    let valid_nested_boundary_package = minimal_collective_setup_package();
    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": valid_nested_boundary_package,
    }))
    .expect("verification response");
    assert_ne!(
        result["refusedObjects"][0]["reasonCode"], "acceptedPathForbiddenField",
        "nested HE target-decryption status must remain allowed"
    );
}

fn premature_target_decryption_artifact(field_name: &str) -> serde_json::Value {
    match field_name {
        "targetDecryptionStatus" => serde_json::json!({
            "targetDecryptionReadiness": "accepted",
            "targetDecryptionProfileId": "BGV-RNS-AsyncTargetDecryption-v1",
        }),
        "targetDecryptionReadiness" => serde_json::json!("accepted"),
        "targetDecryptionCertificate" => serde_json::json!({
            "objectType": "TargetDecryptionCertificate",
            "objectVersion": 1,
            "certificateStatus": "accepted",
        }),
        "targetDecryptionCertificateHash" => serde_json::json!(valid_hash('6')),
        "targetDecryptionClosure" => serde_json::json!({
            "closureStatus": "accepted",
        }),
        "targetDecryptionShareProofs" => serde_json::json!({
            "objectType": "TargetDecryptionShareProofSet",
            "proofRecords": [],
        }),
        "targetDecryptionShares" => serde_json::json!([]),
        "targetPartDecRecords" => serde_json::json!([]),
        "targetC1C4Certificate" => serde_json::json!({
            "objectType": "TargetC1C4Certificate",
            "certificateStatus": "accepted",
        }),
        _ => panic!("unsupported target-decryption artifact {field_name}"),
    }
}

#[test]
fn collective_setup_verifier_refuses_evaluator_schedule_drift() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_evaluator_schedule_drift");
    let mut package = minimal_collective_setup_package();
    package["evaluatorKeySchedule"]["requiredGaloisSetHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "requiredGaloisSetHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_evaluation_key_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_evaluation_key_material",
    );
    let mut relin_package = minimal_collective_setup_package();
    let evaluator_key_schedule_root =
        relin_package["evaluatorKeySchedule"]["evaluatorKeyScheduleRoot"].clone();
    relin_package["relinearizationKeyShareRounds"] = serde_json::json!({
        "evaluatorKeyScheduleRoot": evaluator_key_schedule_root,
    });
    rebind_collective_setup_package_hash(&mut relin_package);

    let relin_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": relin_package,
    }))
    .expect("verification response");

    assert_eq!(relin_result["verifierStatus"], "refused");
    assert_eq!(
        relin_result["refusedObjects"][0]["reasonCode"],
        "relinearizationKeyShareRoundsTypeMismatch"
    );

    let mut evaluation_key_package = minimal_collective_setup_package();
    evaluation_key_package["evaluationKeys"] = serde_json::json!({
        "evaluationKeyRoot": valid_hash('9'),
    });
    rebind_collective_setup_package_hash(&mut evaluation_key_package);

    let evaluation_key_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": evaluation_key_package,
        }))
        .expect("verification response");

    assert_eq!(evaluation_key_result["verifierStatus"], "refused");
    assert_eq!(
        evaluation_key_result["refusedObjects"][0]["reasonCode"],
        "evaluationKeysUnexpectedField"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_evaluation_key_proof_container_roots",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let relinearization_root =
        package["relinearizationKeyShareRounds"]["relinearizationKeyShareRoundsRoot"].clone();
    let first_galois_batch_root =
        package["galoisKeyShareBatches"][0]["galoisKeyShareBatchRoot"].clone();
    let trustee_proof_set_root =
        package["trusteeEvaluationKeyProofs"]["trusteeEvaluationKeyProofSetRoot"].clone();
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"].clone();
    let accepted_hashes = accepted_hashes_from_package(package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    for expected_hash in [
        relinearization_root.as_str().expect("relinearization root"),
        first_galois_batch_root.as_str().expect("Galois batch root"),
        trustee_proof_set_root
            .as_str()
            .expect("trustee evaluation-key proof set root"),
        evaluation_key_set_hash
            .as_str()
            .expect("evaluation key set hash"),
    ] {
        assert!(
            accepted_hashes
                .iter()
                .any(|accepted_hash| accepted_hash == expected_hash),
            "accepted hashes must cover {expected_hash}"
        );
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_transported_public_evaluation_key_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let evaluation_key_set_hash = package["evaluationKeys"]["evaluationKeySetHash"]
        .as_str()
        .expect("evaluation-key set hash")
        .to_string();
    let public_material_root = package["evaluationKeys"]["publicEvaluationKeyMaterialRoot"]
        .as_str()
        .expect("public evaluation-key material root")
        .to_string();
    let accepted_hashes = accepted_hashes_from_package(&package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &evaluation_key_set_hash)
    );
    assert!(
        accepted_hashes
            .iter()
            .any(|accepted_hash| accepted_hash == &public_material_root)
    );
}

#[test]
#[ignore = "manual accepted setup closure diagnostic"]
fn manual_accepted_setup_collective_setup_verifier_accepts_all_transported_public_setup_companions()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "manual_accepted_setup_collective_setup_verifier_accepts_all_transported_public_setup_companions",
    );
    let (package, companions) = setup_package_with_transported_public_setup_companions();

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
        "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
        "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
        "transportedPublicKeyShareMaterial": companions.public_key_share_material,
        "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
        "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
        "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
        "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "accepted",
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(result["currentPhase"], "setupPackageVerification");
    assert_eq!(
        result["acceptedSetupHandoff"]["objectType"],
        "CollectiveBgvAcceptedSetupHandoff"
    );
    assert!(
        result["acceptedSetupHandoff"]["acceptedSetupHandoffRoot"].is_string(),
        "accepted terminal setup response must carry a handoff root"
    );
    let accepted_handoff = &result["acceptedSetupHandoff"];
    assert!(
        accepted_handoff["thresholdProfileHash"].as_str().is_some(),
        "accepted setup handoff must bind the threshold profile used by ballot packages"
    );
    let direct_ballot_handoff = &accepted_handoff["directBallotEncryptionHandoff"];
    assert_eq!(
        direct_ballot_handoff["collectivePublicKeyRoot"],
        package["collectivePublicKey"]["collectivePublicKeyRoot"]
    );
    assert_eq!(
        direct_ballot_handoff["bgvPublicKeyRoot"],
        result["acceptedPublicKeyMaterial"]["bgvPublicKeyRoot"]
    );
    assert_eq!(
        result["acceptedPublicKeyMaterial"]["objectType"],
        "DirectBallotAcceptedPublicKeyMaterial"
    );
    assert_eq!(
        result["acceptedPublicKeyMaterial"]["acceptedSetupHandoffRoot"],
        accepted_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        direct_ballot_handoff["bgvProfileHash"],
        crate::bgv::profile::profile_hash().expect("BGV profile hash")
    );
    assert_eq!(
        direct_ballot_handoff["batchEncoderHash"],
        crate::bgv::profile::batch_encoder_hash().expect("batch encoder hash")
    );
    assert_eq!(
        direct_ballot_handoff["encryptedBallotLayoutHash"],
        crate::bgv::profile::encrypted_ballot_layout_hash().expect("encrypted ballot layout hash")
    );
    assert_eq!(
        direct_ballot_handoff["ballotValidityProofProfileHash"],
        crate::bgv::direct_ballots::direct_ballot_relation_proof_profile_hash()
            .expect("direct ballot proof profile hash")
    );
    assert_eq!(
        direct_ballot_handoff["arithmeticCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_arithmetic_certificate_hash()
            .expect("direct ballot arithmetic certificate hash")
    );
    assert_eq!(
        direct_ballot_handoff["soundnessCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_soundness_certificate_hash()
            .expect("direct ballot soundness certificate hash")
    );
    assert_eq!(
        direct_ballot_handoff["zeroKnowledgeCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_zero_knowledge_certificate_hash()
            .expect("direct ballot zero-knowledge certificate hash")
    );
    assert_eq!(
        direct_ballot_handoff["verifierCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_verifier_certificate_hash()
            .expect("direct ballot verifier certificate hash")
    );
    assert_eq!(
        direct_ballot_handoff["acceptedPublicKeyMaterial"]["publicKeyShareMaterialSetRoot"],
        package["publicKeyShareMaterial"]["publicKeyShareMaterialSetRoot"]
    );
    assert!(
        direct_ballot_handoff
            .get("supportedBallotCreationPolicy")
            .is_none(),
        "accepted setup handoff must bind the direct ballot creation policy by hash, not embed the policy body"
    );
    assert_eq!(
        direct_ballot_handoff["supportedBallotCreationPolicyHash"],
        direct_ballot_creation_policy_hash().expect("direct ballot creation policy hash")
    );
    let ballot_creation_policy =
        direct_ballot_creation_policy_value().expect("direct ballot creation policy");
    assert_eq!(
        ballot_creation_policy["acceptedPackageObjectType"],
        "EncryptedBallotPackage"
    );
    assert_eq!(
        ballot_creation_policy["validityStatementId"],
        "BallotValidityStatement-v1"
    );
    assert_eq!(
        ballot_creation_policy["arithmeticCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_arithmetic_certificate_hash()
            .expect("direct ballot arithmetic certificate hash")
    );
    assert_eq!(
        ballot_creation_policy["soundnessCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_soundness_certificate_hash()
            .expect("direct ballot soundness certificate hash")
    );
    assert_eq!(
        ballot_creation_policy["zeroKnowledgeCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_zero_knowledge_certificate_hash()
            .expect("direct ballot zero-knowledge certificate hash")
    );
    assert_eq!(
        ballot_creation_policy["verifierCertificateHash"],
        crate::bgv::direct_ballots::direct_ballot_verifier_certificate_hash()
            .expect("direct ballot verifier certificate hash")
    );
    assert_eq!(ballot_creation_policy["optionCount"], 20);
    assert_eq!(ballot_creation_policy["scoreDomain"]["minimum"], 1);
    assert_eq!(ballot_creation_policy["scoreDomain"]["maximum"], 10);
    assert_eq!(ballot_creation_policy["scoreDomain"]["bucketCount"], 10);
    assert_eq!(ballot_creation_policy["plaintextModulus"], 65_537);
    for forbidden_field_name in [
        "scoreHash",
        "plaintextScores",
        "encryptionRandomness",
        "proofWitness",
        "fixtureSeed",
        "developmentPlaintext",
    ] {
        assert!(
            ballot_creation_policy["forbiddenPackageFields"]
                .as_array()
                .expect("forbidden package fields")
                .iter()
                .any(|field_name| field_name.as_str() == Some(forbidden_field_name)),
            "ballot creation policy must forbid {forbidden_field_name}"
        );
    }
    let handoff_json =
        serde_json::to_string(accepted_handoff).expect("accepted setup handoff JSON");
    for forbidden_fragment in [
        "setupSeed",
        "setupPrivateWitness",
        "proofRandomnessSeedHex",
        "developmentPlaintext",
    ] {
        assert!(
            !handoff_json.contains(forbidden_fragment),
            "accepted setup handoff must not contain {forbidden_fragment}"
        );
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_output_drives_direct_encrypted_ballot_package_flow() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_output_drives_direct_encrypted_ballot_package_flow",
    );
    let (package, companions) = setup_package_with_transported_public_setup_companions();

    let setup_verification = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
        "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
        "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
        "transportedPublicKeyShareMaterial": companions.public_key_share_material,
        "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
        "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
        "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
        "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
    }))
    .expect("accepted setup verification response");

    assert_eq!(
        setup_verification["verifierStatus"],
        "accepted",
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&setup_verification)
            .expect("terminal setup verification JSON")
    );
    terminal_phase("verified accepted setup package");

    let accepted_setup_handoff = setup_verification["acceptedSetupHandoff"].clone();
    let accepted_public_key_material = setup_verification["acceptedPublicKeyMaterial"].clone();
    let setup_context = &package["setupContext"];
    assert_eq!(
        setup_context["participantCount"],
        serde_json::json!(10),
        "direct-route setup fixture must use the first-profile roster size"
    );
    assert_eq!(setup_context["qSetupComplete"], serde_json::json!(10));
    assert_eq!(setup_context["qBallotRelease"], serde_json::json!(10));
    assert_eq!(setup_context["qFinal"], serde_json::json!(10));
    assert_eq!(setup_context["qDec"], serde_json::json!(4));
    assert_eq!(
        accepted_public_key_material["objectType"],
        "DirectBallotAcceptedPublicKeyMaterial"
    );
    assert_eq!(
        accepted_setup_handoff["ceremonyId"],
        setup_context["ceremonyId"]
    );
    assert_eq!(
        accepted_setup_handoff["manifestHash"],
        setup_context["manifestHash"]
    );
    assert_eq!(
        accepted_setup_handoff["rosterHash"],
        setup_context["rosterHash"]
    );
    assert_eq!(
        accepted_setup_handoff["setupProfileHash"],
        setup_context["setupProfileHash"]
    );
    assert_eq!(
        accepted_public_key_material["ceremonyId"],
        setup_context["ceremonyId"]
    );
    assert_eq!(
        accepted_public_key_material["manifestHash"],
        setup_context["manifestHash"]
    );
    assert_eq!(
        accepted_public_key_material["rosterHash"],
        setup_context["rosterHash"]
    );
    assert_eq!(
        accepted_public_key_material["setupPackageHash"],
        package["setupPackageHash"]
    );
    assert_eq!(
        accepted_public_key_material["thresholdProfileHash"],
        accepted_setup_handoff["thresholdProfileHash"]
    );
    assert_eq!(
        accepted_public_key_material["acceptedSetupHandoffRoot"],
        accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        accepted_public_key_material["collectivePublicKeyRoot"],
        package["collectivePublicKey"]["collectivePublicKeyRoot"]
    );
    assert_eq!(
        accepted_public_key_material["bgvPublicKeyRoot"],
        accepted_setup_handoff["directBallotEncryptionHandoff"]["bgvPublicKeyRoot"]
    );
    assert_eq!(
        direct_ballot_creation_policy_value().expect("direct ballot creation policy")["optionCount"],
        serde_json::json!(20)
    );
    assert_eq!(
        direct_ballot_creation_policy_value().expect("direct ballot creation policy")["scoreDomain"]
            ["minimum"],
        serde_json::json!(1)
    );
    assert_eq!(
        direct_ballot_creation_policy_value().expect("direct ballot creation policy")["scoreDomain"]
            ["maximum"],
        serde_json::json!(10)
    );
    terminal_phase("checked direct ballot setup-output bindings");

    let ballot_encryption_seed_hex = "11".repeat(32);
    let proof_mask_seed_hex = "22".repeat(32);
    let action_context_hash = derive_protocol_hash(
        "ActionContextHash",
        &serde_json::json!({
            "action": "accepted setup output direct encrypted ballot package flow",
            "ballotIndex": 0
        }),
    )
    .expect("action context hash");
    let ballots = serde_json::json!([{
        "voterIdentity": "voter-accepted-setup-output",
        "voterRosterPosition": 0,
        "actionContextHash": action_context_hash,
        "recoveryEpoch": 0,
        "deviceEpoch": 0,
        "scores": [
            10, 9, 8, 7, 6,
            5, 4, 3, 2, 1,
            1, 2, 3, 4, 5,
            6, 7, 8, 9, 10
        ]
    }]);

    let mut drifted_public_key_material = accepted_public_key_material.clone();
    drifted_public_key_material["acceptedSetupHandoffRoot"] = serde_json::json!("0".repeat(128));
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: drifted_public_key_material,
            accepted_setup_handoff: accepted_setup_handoff.clone(),
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::ProfileComponentMismatch,
            expected_message_fragment: "acceptedPublicKeyMaterial.acceptedSetupHandoffRoot",
            case_label: "accepted public-key material rebound to another setup handoff",
        },
    );

    let mut drifted_bgv_root_material = accepted_public_key_material.clone();
    drifted_bgv_root_material["bgvPublicKeyRoot"] = serde_json::json!("0".repeat(128));
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: drifted_bgv_root_material,
            accepted_setup_handoff: accepted_setup_handoff.clone(),
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::ProfileComponentMismatch,
            expected_message_fragment: "acceptedPublicKeyMaterial.bgvPublicKeyRoot",
            case_label: "accepted public-key material with drifted BGV public-key root",
        },
    );

    let mut setup_root_handoff = accepted_setup_handoff.clone();
    setup_root_handoff["setupPackageHash"] = serde_json::json!("0".repeat(128));
    rebind_setup_output_handoff_root(&mut setup_root_handoff);
    let mut setup_root_material = accepted_public_key_material.clone();
    setup_root_material["acceptedSetupHandoffRoot"] =
        setup_root_handoff["acceptedSetupHandoffRoot"].clone();
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: setup_root_material,
            accepted_setup_handoff: setup_root_handoff,
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::ProfileComponentMismatch,
            expected_message_fragment: "acceptedPublicKeyMaterial.setupPackageHash",
            case_label: "accepted setup handoff rebound to another setup package root",
        },
    );

    let mut soundness_handoff = accepted_setup_handoff.clone();
    soundness_handoff["directBallotEncryptionHandoff"]["soundnessCertificateHash"] =
        serde_json::json!("0".repeat(128));
    rebind_setup_output_handoff_root(&mut soundness_handoff);
    let mut soundness_material = accepted_public_key_material.clone();
    soundness_material["acceptedSetupHandoffRoot"] =
        soundness_handoff["acceptedSetupHandoffRoot"].clone();
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: soundness_material,
            accepted_setup_handoff: soundness_handoff,
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::ProfileComponentMismatch,
            expected_message_fragment: "directBallotEncryptionHandoff.soundnessCertificateHash",
            case_label: "accepted setup handoff with drifted direct-ballot soundness certificate",
        },
    );

    let mut public_key_summary_handoff = accepted_setup_handoff.clone();
    public_key_summary_handoff["directBallotEncryptionHandoff"]["acceptedPublicKeyMaterial"]["publicKeyShareMaterialSetRoot"] =
        serde_json::json!("0".repeat(128));
    rebind_setup_output_handoff_root(&mut public_key_summary_handoff);
    let mut public_key_summary_material = accepted_public_key_material.clone();
    public_key_summary_material["acceptedSetupHandoffRoot"] =
        public_key_summary_handoff["acceptedSetupHandoffRoot"].clone();
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: public_key_summary_material,
            accepted_setup_handoff: public_key_summary_handoff,
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::ProfileComponentMismatch,
            expected_message_fragment: "acceptedPublicKeyMaterial.publicKeyShareMaterialSetRoot",
            case_label: "accepted setup handoff with drifted embedded public-key summary",
        },
    );

    let mut leaking_public_key_material = accepted_public_key_material.clone();
    leaking_public_key_material["collectivePublicKey"]["setupPrivateWitness"] =
        serde_json::json!({ "setupSeed": "must-not-enter-public-ballot-path" });
    assert_direct_ballot_creation_rejects_setup_output_drift(
        DirectBallotSetupOutputDriftExpectation {
            accepted_public_key_material: leaking_public_key_material,
            accepted_setup_handoff: accepted_setup_handoff.clone(),
            ballot_encryption_seed_hex: &ballot_encryption_seed_hex,
            proof_mask_seed_hex: &proof_mask_seed_hex,
            ballots: &ballots,
            expected_code: CanonicalErrorCode::InvalidFixture,
            expected_message_fragment: "setupPrivateWitness",
            case_label: "accepted public-key material containing leaked setup witness fields",
        },
    );
    terminal_phase("checked direct ballot setup-output refusal matrix");

    let package_creation = create_direct_encrypted_ballot_packages(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "ballotEncryptionRandomness": {
            "source": "fresh-csprng",
            "encryptionSeedHexes": [ballot_encryption_seed_hex]
        },
        "proofMaskRandomness": {
            "source": "fresh-csprng",
            "ballotProofRandomnessHexes": [proof_mask_seed_hex]
        },
        "ballots": ballots
    }))
    .expect("direct ballot package creation consumes accepted setup verifier output");
    terminal_phase("created direct encrypted ballot package");

    assert_eq!(
        package_creation["operation"],
        "createDirectEncryptedBallotPackages"
    );
    assert_eq!(
        package_creation["packageCreation"]["setupHandoffRoot"],
        accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        package_creation["proofAttempt"]["proofTransport"]["chunksPerProof"],
        package_creation["encryptedBallotPackages"][0]["proofChunkManifest"]["chunkCount"]
    );
    assert_eq!(
        package_creation["proofAttempt"]["proofCostEvidence"]["proofSizeBytes"],
        package_creation["proofAttempt"]["proofSizeBytes"]
    );
    assert_eq!(
        package_creation["proofAttempt"]["proofCostEvidence"]["proofChunkCount"],
        package_creation["proofAttempt"]["proofTransport"]["chunksPerProof"]
    );

    let package_record = package_creation["encryptedBallotPackages"][0].clone();
    let signature_fixture = create_protocol_signature_fixture(
        "accepted-setup-output-direct-ballot-voter",
        package_record["voterSignatureSignedRoot"].clone(),
    )
    .expect("voter signature fixture");
    let mut signed_package = package_record["encryptedBallotPackage"].clone();
    signed_package["signature"] = signature_fixture.envelope.clone();
    let voter_signing_public_key_hash = signature_fixture.public_key_hash.clone();

    let package_verification = verify_direct_encrypted_ballot_package(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
        "encryptedBallotPackage": signed_package.clone(),
        "proofChunks": package_record["proofChunks"].clone(),
    }))
    .expect("direct ballot package verification consumes accepted setup verifier output");
    terminal_phase("verified direct encrypted ballot package");

    assert_eq!(
        package_verification["operation"],
        "verifyDirectEncryptedBallotPackage"
    );
    assert_eq!(
        package_verification["acceptedSetupHandoffRoot"],
        accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        package_verification["packageVerificationCertificate"]["publicAggregationInput"]["acceptedSetupHandoffRoot"],
        accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(
        package_verification["packageVerificationCertificate"]["publicAggregationInput"]["proofProfileHash"],
        package_record["encryptedBallotPackage"]["proofProfileHash"]
    );
    assert_eq!(
        package_verification["packageVerificationCertificate"]["publicAggregationInput"]["proofChunkRoot"],
        package_record["proofChunkManifestRoot"]
    );
    assert_eq!(
        package_verification["packageVerificationCertificate"]["packageVerificationCertificateHash"],
        package_verification["packageVerificationCertificateHash"]
    );
    let mut package_verification_certificate_hash_input =
        package_verification["packageVerificationCertificate"].clone();
    package_verification_certificate_hash_input
        .as_object_mut()
        .expect("package verification certificate object")
        .remove("packageVerificationCertificateHash");
    let expected_package_verification_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotPackageVerificationCertificateHash",
        &package_verification_certificate_hash_input,
    )
    .expect("package verification certificate hash");
    assert_eq!(
        package_verification["packageVerificationCertificateHash"].as_str(),
        Some(expected_package_verification_certificate_hash.as_str())
    );
    let mut drifted_package_verification_certificate_hash_input =
        package_verification["packageVerificationCertificate"].clone();
    drifted_package_verification_certificate_hash_input["acceptedSetupHandoffRoot"] =
        serde_json::json!("0".repeat(128));
    drifted_package_verification_certificate_hash_input
        .as_object_mut()
        .expect("drifted package verification certificate object")
        .remove("packageVerificationCertificateHash");
    let drifted_package_verification_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotPackageVerificationCertificateHash",
        &drifted_package_verification_certificate_hash_input,
    )
    .expect("drifted package verification certificate hash");
    assert_ne!(
        package_verification["packageVerificationCertificateHash"].as_str(),
        Some(drifted_package_verification_certificate_hash.as_str())
    );

    let mut tampered_proof_chunks = package_record["proofChunks"].clone();
    let first_chunk_bytes_hex = tampered_proof_chunks[0]["bytesHex"]
        .as_str()
        .expect("first proof chunk bytes");
    let replacement_prefix = if first_chunk_bytes_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered_proof_chunks[0]["bytesHex"] = serde_json::json!(format!(
        "{replacement_prefix}{}",
        &first_chunk_bytes_hex[1..]
    ));
    let tampered_chunk_error = verify_direct_encrypted_ballot_package(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
        "encryptedBallotPackage": signed_package.clone(),
        "proofChunks": tampered_proof_chunks,
    }))
    .expect_err("direct ballot package verification must reject tampered proof chunks from real setup output");
    assert_eq!(
        tampered_chunk_error.code,
        CanonicalErrorCode::InvalidFixture
    );
    assert!(
        tampered_chunk_error
            .message
            .contains("proofChunks[0] bytes do not match chunkHash"),
        "unexpected tampered proof-chunk refusal: {}",
        tampered_chunk_error.message
    );

    let mut tampered_signature_package = signed_package.clone();
    let signature_bytes_hex = tampered_signature_package["signature"]["signatureBytesHex"]
        .as_str()
        .expect("signature bytes hex");
    let replacement_prefix = if signature_bytes_hex.starts_with('0') {
        "1"
    } else {
        "0"
    };
    tampered_signature_package["signature"]["signatureBytesHex"] =
        serde_json::json!(format!("{replacement_prefix}{}", &signature_bytes_hex[1..]));
    let tampered_signature_error = verify_direct_encrypted_ballot_package(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
        "encryptedBallotPackage": tampered_signature_package,
        "proofChunks": package_record["proofChunks"].clone(),
    }))
    .expect_err("direct ballot package verification must reject tampered voter signatures from real setup output");
    assert_eq!(
        tampered_signature_error.code,
        CanonicalErrorCode::InvalidFixture
    );
    assert!(
        tampered_signature_error
            .message
            .contains("Signature hash does not verify for the canonical signed root"),
        "unexpected tampered signature refusal: {}",
        tampered_signature_error.message
    );
    terminal_phase("checked direct ballot package refusal matrix");

    let first_valid_mismatch_error =
        aggregate_direct_encrypted_ballot_packages(&serde_json::json!({
            "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
            "acceptedSetupHandoff": accepted_setup_handoff.clone(),
            "firstValidOrderHash": "0".repeat(128),
            "firstValidPackageRoots": ["1".repeat(128)],
            "encryptedBallotPackages": [{
                "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
                "encryptedBallotPackage": signed_package.clone(),
                "proofChunks": package_record["proofChunks"].clone(),
            }]
        }))
        .expect_err("direct ballot aggregation must reject first-valid roots that do not match real setup-output packages");
    assert_eq!(
        first_valid_mismatch_error.code,
        CanonicalErrorCode::ProfileComponentMismatch
    );
    assert!(
        first_valid_mismatch_error
            .message
            .contains("firstValidPackageRoots must exactly match"),
        "unexpected first-valid mismatch refusal: {}",
        first_valid_mismatch_error.message
    );

    let duplicate_package_error = aggregate_direct_encrypted_ballot_packages(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material.clone(),
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "encryptedBallotPackages": [
            {
                "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
                "encryptedBallotPackage": signed_package.clone(),
                "proofChunks": package_record["proofChunks"].clone(),
            },
            {
                "voterSigningPublicKeyHash": voter_signing_public_key_hash.clone(),
                "encryptedBallotPackage": signed_package.clone(),
                "proofChunks": package_record["proofChunks"].clone(),
            }
        ]
    }))
    .expect_err(
        "direct ballot aggregation must reject duplicate package replay from real setup output",
    );
    assert_eq!(
        duplicate_package_error.code,
        CanonicalErrorCode::InvalidFixture
    );
    assert!(
        duplicate_package_error
            .message
            .contains("duplicates a package root"),
        "unexpected duplicate package refusal: {}",
        duplicate_package_error.message
    );

    let aggregate = aggregate_direct_encrypted_ballot_packages(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material,
        "acceptedSetupHandoff": accepted_setup_handoff.clone(),
        "encryptedBallotPackages": [{
            "voterSigningPublicKeyHash": voter_signing_public_key_hash,
            "encryptedBallotPackage": signed_package,
            "proofChunks": package_record["proofChunks"].clone(),
        }]
    }))
    .expect("direct ballot aggregation consumes accepted setup verifier output");
    terminal_phase("aggregated direct encrypted ballot package");

    assert_eq!(
        aggregate["operation"],
        "aggregateDirectEncryptedBallotPackages"
    );
    assert_eq!(
        aggregate["acceptedSetupHandoffRoot"],
        accepted_setup_handoff["acceptedSetupHandoffRoot"]
    );
    assert_eq!(aggregate["ballotCount"], 1);
    assert_eq!(
        aggregate["aggregateCertificate"]["packageVerificationInputs"][0]["packageRoot"],
        package_record["encryptedBallotPackageRoot"]
    );
    assert_eq!(
        aggregate["aggregateCertificate"]["aggregateCertificateHash"],
        aggregate["aggregateCertificateHash"]
    );
    let mut aggregate_certificate_hash_input = aggregate["aggregateCertificate"].clone();
    aggregate_certificate_hash_input
        .as_object_mut()
        .expect("aggregate certificate object")
        .remove("aggregateCertificateHash");
    let expected_aggregate_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotAggregateCertificateHash",
        &aggregate_certificate_hash_input,
    )
    .expect("aggregate certificate hash");
    assert_eq!(
        aggregate["aggregateCertificateHash"].as_str(),
        Some(expected_aggregate_certificate_hash.as_str())
    );
    let mut drifted_aggregate_certificate_hash_input = aggregate["aggregateCertificate"].clone();
    drifted_aggregate_certificate_hash_input["ballotCount"] = serde_json::json!(2);
    drifted_aggregate_certificate_hash_input
        .as_object_mut()
        .expect("drifted aggregate certificate object")
        .remove("aggregateCertificateHash");
    let drifted_aggregate_certificate_hash = derive_protocol_hash(
        "DirectEncryptedBallotAggregateCertificateHash",
        &drifted_aggregate_certificate_hash_input,
    )
    .expect("drifted aggregate certificate hash");
    assert_ne!(
        aggregate["aggregateCertificateHash"].as_str(),
        Some(drifted_aggregate_certificate_hash.as_str())
    );
}

struct DirectBallotSetupOutputDriftExpectation<'a> {
    accepted_public_key_material: serde_json::Value,
    accepted_setup_handoff: serde_json::Value,
    ballot_encryption_seed_hex: &'a str,
    proof_mask_seed_hex: &'a str,
    ballots: &'a serde_json::Value,
    expected_code: CanonicalErrorCode,
    expected_message_fragment: &'a str,
    case_label: &'a str,
}

fn assert_direct_ballot_creation_rejects_setup_output_drift(
    expectation: DirectBallotSetupOutputDriftExpectation<'_>,
) {
    let DirectBallotSetupOutputDriftExpectation {
        accepted_public_key_material,
        accepted_setup_handoff,
        ballot_encryption_seed_hex,
        proof_mask_seed_hex,
        ballots,
        expected_code,
        expected_message_fragment,
        case_label,
    } = expectation;

    let error = match create_direct_encrypted_ballot_packages(&serde_json::json!({
        "acceptedPublicKeyMaterial": accepted_public_key_material,
        "acceptedSetupHandoff": accepted_setup_handoff,
        "ballotEncryptionRandomness": {
            "source": "fresh-csprng",
            "encryptionSeedHexes": [ballot_encryption_seed_hex]
        },
        "proofMaskRandomness": {
            "source": "fresh-csprng",
            "ballotProofRandomnessHexes": [proof_mask_seed_hex]
        },
        "ballots": ballots.clone()
    })) {
        Ok(result) => panic!(
            "{case_label} unexpectedly accepted before direct ballot proof generation: {}",
            serde_json::to_string_pretty(&result).expect("accepted package result JSON")
        ),
        Err(error) => error,
    };

    assert_eq!(
        error.code, expected_code,
        "{case_label} produced the wrong refusal code: {}",
        error.message
    );
    assert!(
        error.message.contains(expected_message_fragment),
        "{case_label} produced unexpected refusal: {}",
        error.message
    );
}

fn rebind_setup_output_handoff_root(accepted_setup_handoff: &mut serde_json::Value) {
    accepted_setup_handoff
        .as_object_mut()
        .expect("accepted setup handoff is an object")
        .remove("acceptedSetupHandoffRoot");
    let accepted_setup_handoff_root =
        derive_protocol_hash("AcceptedSetupHandoffRoot", accepted_setup_handoff)
            .expect("accepted setup handoff root");
    accepted_setup_handoff["acceptedSetupHandoffRoot"] =
        serde_json::json!(accepted_setup_handoff_root);
}

#[test]
fn collective_setup_verifier_refuses_drifted_terminal_certificate_hashes() {
    // Drifting a present certificate hash and recomputing the outer package hash
    // must be refused before any missing-object pending, proving the verifier
    // recomputes each certificate root rather than trusting the package copy.
    for certificate_hash_field in [
        "setupCommitmentSecurityCertificateHash",
        "setupTransportCertificateHash",
        "setupProofAccountingCertificateHash",
        "heSecurityCertificateHash",
        "activeStaticSetupTheoremCertificateHash",
    ] {
        let mut package = minimal_collective_setup_package();
        let bound_hash = package[certificate_hash_field]
            .as_str()
            .unwrap_or_else(|| panic!("{certificate_hash_field} must be present"))
            .to_string();
        package[certificate_hash_field] = serde_json::json!(drift_hash(&bound_hash));
        rebind_collective_setup_package_hash(&mut package);

        let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .expect("verification response");

        assert_eq!(
            result["verifierStatus"], "refused",
            "drifting {certificate_hash_field} must refuse before any missing-object pending",
        );
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_refuses_every_recomputed_accepted_root_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_refuses_every_recomputed_accepted_root_drift",
    );
    let (package, companions) = setup_package_with_transported_public_setup_companions();
    let verify = |candidate: &serde_json::Value| {
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": candidate,
            "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
            "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
            "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
            "transportedPublicKeyShareMaterial": companions.public_key_share_material,
            "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
            "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
            "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
            "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
        }))
        .expect("verification response")
    };

    terminal_phase("verifying baseline terminal package before recomputed-root matrix");
    assert_eq!(
        verify(&package)["verifierStatus"],
        "accepted",
        "baseline terminal package must accept before the recomputed-root matrix",
    );
    terminal_phase("verified baseline terminal package before recomputed-root matrix");

    // The matrix is driven by the verifier's own accepted-root enumeration, so it
    // covers exactly the root set the accept response binds: every accepted root,
    // drifted at every occurrence with the outer package hash recomputed, must be
    // refused. A root the verifier never recomputes would silently survive here.
    let accepted_roots = crate::bgv::setup::accepted_setup::accepted_hashes_from_package(&package);
    let package_hash = package["setupPackageHash"]
        .as_str()
        .expect("setup package hash")
        .to_string();
    let unique_accepted_roots = accepted_roots
        .iter()
        .filter(|root| *root != &package_hash)
        .cloned()
        .collect::<std::collections::BTreeSet<_>>();
    terminal_phase(&format!(
        "checking recomputed-root matrix over {} unique accepted roots",
        unique_accepted_roots.len()
    ));

    let mut unbound_roots = Vec::new();
    let mut covered_root_count = 0_usize;
    for root in &unique_accepted_roots {
        let mut drifted = package.clone();
        let occurrences = drift_all_occurrences(&mut drifted, root, &drift_hash(root));
        assert!(
            occurrences >= 1,
            "accepted root {root} was not located in the terminal package graph",
        );
        rebind_collective_setup_package_hash(&mut drifted);
        if verify(&drifted)["verifierStatus"] != "refused" {
            unbound_roots.push(root.clone());
        }
        covered_root_count += 1;
        terminal_phase(&format!(
            "checked recomputed-root drift {covered_root_count}/{}",
            unique_accepted_roots.len()
        ));
    }
    assert!(
        unbound_roots.is_empty(),
        "terminal package accepted roots that the verifier does not recompute and refuse: {unbound_roots:?}",
    );
    assert!(
        covered_root_count >= 12,
        "completeness floor: the terminal accepted package must bind the full first-profile root set, covered {covered_root_count}",
    );

    // Drifting the outer package hash without recomputation is a package-hash
    // mismatch, the structural guard the per-root rebinds rely on.
    let mut drifted_package_hash = package.clone();
    drifted_package_hash["setupPackageHash"] = serde_json::json!(drift_hash(&package_hash));
    assert_eq!(
        verify(&drifted_package_hash)["verifierStatus"],
        "refused",
        "drifting the outer setup package hash must be refused",
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_terminal_trustee_proof_statement_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_terminal_trustee_proof_statement_hash_drift",
    );
    let (mut package, companions) = setup_package_with_transported_public_setup_companions();

    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_trustee_evaluation_key_proof_record_root(&mut package, 0);
    rebind_trustee_evaluation_key_proof_set_root(&mut package);
    rebind_setup_key_correctness_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": companions.vss_coefficient_commitment_material,
        "verifiedVssCoefficientCommitmentMaterial": companions.verified_vss_coefficient_commitment_material,
        "transportedSameSecretProofMaterial": companions.same_secret_proof_material,
        "transportedPublicKeyShareMaterial": companions.public_key_share_material,
        "transportedPublicKeyShareProofMaterial": companions.public_key_share_proof_material,
        "transportedEvaluationKeyShareComponentMaterial": companions.evaluation_key_share_component_material,
        "transportedEvaluationKeyShareProofMaterial": companions.evaluation_key_share_proof_material,
        "transportedPublicEvaluationKeyMaterial": companions.public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "refused",
        "terminal setup verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("statementHash must match the statement rebuilt")
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_public_evaluation_key_material_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);
    let expected_manifest =
        public_evaluation_key_material_manifest(&package, &package["evaluationKeys"])
            .expect("public evaluation-key material manifest");
    let mut tampered_manifest = expected_manifest;
    tampered_manifest["materialSource"] =
        serde_json::json!("tampered-public-evaluation-key-material");
    let tampered_material_bytes =
        encode_public_evaluation_key_material_manifest(&tampered_manifest)
            .expect("tampered public evaluation-key material bytes");
    rebind_public_evaluation_key_material_transport(
        &mut package,
        &mut transported_public_evaluation_key_material,
        tampered_material_bytes,
    );

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "publicEvaluationKeyMaterialManifestMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_uses_request_side_evaluation_key_component_chunks()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_uses_request_side_evaluation_key_component_chunks",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let component_material_set =
        move_first_galois_key_share_component_vectors_to_transport(&mut package);
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareComponentMaterial": component_material_set,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_trustee_proofs_from_transported_proof_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_trustee_proofs_from_transported_proof_material",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let proof_material_set =
        move_first_trustee_evaluation_key_proof_bytes_to_transport(&mut package);
    let transported_public_evaluation_key_material =
        add_public_evaluation_key_material_transport(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": proof_material_set,
        "transportedPublicEvaluationKeyMaterial": transported_public_evaluation_key_material,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"],
        "outsideProfile",
        "unexpected verification result: {}",
        serde_json::to_string_pretty(&result).expect("verification result JSON")
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialOutsideProfile"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_trustee_proof_chunk()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_transported_trustee_proof_chunk",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    let mut proof_material_set =
        move_first_trustee_evaluation_key_proof_bytes_to_transport(&mut package);
    let chunk_bytes_hex = proof_material_set["proofMaterials"][0]["chunks"][0]["bytesHex"]
        .as_str()
        .expect("transported proof chunk bytes")
        .to_string();
    let mut tampered = chunk_bytes_hex.into_bytes();
    tampered[0] = if tampered[0] == b'0' { b'1' } else { b'0' };
    proof_material_set["proofMaterials"][0]["chunks"][0]["bytesHex"] =
        serde_json::json!(String::from_utf8(tampered).expect("tampered chunk hex"));

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedEvaluationKeyShareProofMaterial": proof_material_set,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_galois_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error =
        match accepted_setup_public_galois_keys_from_transport(package, &serde_json::json!({})) {
            Ok(_) => panic!("reduced-ring material must not become runtime Galois keys"),
            Err(error) => error,
        };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_public_relinearization_key_loader_refuses_reduced_ring_material",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();

    let error = match accepted_setup_public_relinearization_keys_from_transport(
        package,
        &serde_json::json!({}),
    ) {
        Ok(_) => panic!("reduced-ring material must not become runtime relinearization keys"),
        Err(error) => error,
    };

    assert_eq!(error.code, CanonicalErrorCode::InvalidFixture);
    assert!(
        error
            .message
            .contains("requires profile-ring component vectors")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_round_two_aggregate_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundTwoAggregateRoots"][0]["roundTwoAggregateRoot"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationRoundTwoAggregateRootMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_relinearization_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["roundOneRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('3'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled level and round")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_trustee_specific_key_switch_seed",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["galoisKeyShareMaterialRecords"][0]["keySwitchSeedHex"] =
        serde_json::json!(valid_hash('2'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("shared by scheduled rotation and level")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_galois_batch_schedule_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["galoisKeyShareBatches"][0]["requiredGaloisKeySchedule"][0]["rotation"] =
        serde_json::json!(9_999);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "evaluationKeyMaterialVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("frozen RequiredGaloisSetHash and schedule")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_evaluation_key_same_secret_family_root_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["relinearizationKeyShareRounds"]["sameSecretProofSetRoot"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "relinearizationKeyShareRoundsBindingMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_missing_trustee_evaluation_key_proofs() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_missing_trustee_evaluation_key_proofs",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package object")
        .remove("trusteeEvaluationKeyProofs");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofsMissing"
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.trusteeEvaluationKeyProofs"
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_malformed_trustee_evaluation_key_proof_container()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_malformed_trustee_evaluation_key_proof_container",
    );

    for field_name in ["proofRecords", "trusteeEvaluationKeyProofSetRoot"] {
        let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
        package["trusteeEvaluationKeyProofs"]
            .as_object_mut()
            .expect("trustee evaluation-key proof set")
            .remove(field_name);
        rebind_collective_setup_package_hash(&mut package);

        let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": package,
        }))
        .expect("verification response");

        assert_eq!(result["verifierStatus"], "refused");
        assert_eq!(
            result["refusedObjects"][0]["reasonCode"],
            "trusteeEvaluationKeyProofVerificationFailed"
        );
        assert!(
            result["refusedObjects"][0]["message"]
                .as_str()
                .expect("refusal message")
                .contains(field_name)
        );
        assert_eq!(
            result["refusedObjects"][0]["objectPath"],
            "setupPackage.trusteeEvaluationKeyProofs"
        );
        assert!(result["acceptedSetupHandoff"].is_null());
    }
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_trustee_evaluation_key_proofs()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_extra_and_duplicate_trustee_evaluation_key_proofs",
    );

    let mut extra_proof_package = evaluation_key_proof_container_bearing_collective_setup_package();
    let duplicate_proof_record =
        extra_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][0].clone();
    extra_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"]
        .as_array_mut()
        .expect("trustee evaluation-key proof records")
        .push(duplicate_proof_record);
    rebind_trustee_evaluation_key_proof_set_root(&mut extra_proof_package);
    rebind_setup_key_correctness_certificate(&mut extra_proof_package);
    rebind_collective_setup_package_hash(&mut extra_proof_package);
    assert_refuses_trustee_evaluation_key_proof_variant(
        extra_proof_package,
        "proofRecords must contain one proof per trustee",
    );

    let mut duplicate_proof_package =
        evaluation_key_proof_container_bearing_collective_setup_package();
    duplicate_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][1] =
        duplicate_proof_package["trusteeEvaluationKeyProofs"]["proofRecords"][0].clone();
    rebind_trustee_evaluation_key_proof_record_root(&mut duplicate_proof_package, 1);
    rebind_trustee_evaluation_key_proof_set_root(&mut duplicate_proof_package);
    rebind_setup_key_correctness_certificate(&mut duplicate_proof_package);
    rebind_collective_setup_package_hash(&mut duplicate_proof_package);
    assert_refuses_trustee_evaluation_key_proof_variant(
        duplicate_proof_package,
        "proof records must be ordered by roster position",
    );
}

fn assert_refuses_trustee_evaluation_key_proof_variant(
    package: serde_json::Value,
    message_fragment: &str,
) {
    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert_eq!(
        result["refusedObjects"][0]["objectPath"],
        "setupPackage.trusteeEvaluationKeyProofs"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains(message_fragment)
    );
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
fn collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_trustee_evaluation_key_proofs_without_share_records",
    );
    let mut package = minimal_collective_setup_package();
    package["trusteeEvaluationKeyProofs"] = serde_json::json!({
        "objectType": "TrusteeEvaluationKeyProofSet",
    });
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofsWithoutShareRecords"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_accounting_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_accounting_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["trusteeEvaluationKeyProofs"]["proofAccountingHash"] =
        serde_json::json!(valid_hash('1'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("proofAccountingHash")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_statement_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_trustee_proof_statement_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["trusteeEvaluationKeyProofs"]["proofRecords"][0]["statementHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("statementHash must match the statement rebuilt")
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_tampered_trustee_proof_bytes() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_tampered_trustee_proof_bytes",
    );
    let package = evaluation_key_proof_container_bearing_collective_setup_package();

    let mut noncanonical_claim_package = package.clone();
    mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
        &mut noncanonical_claim_package,
        |proof_bytes| {
            set_first_masked_consistency_claim_to_noncanonical_modulus(proof_bytes);
        },
    );
    let noncanonical_claim_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": noncanonical_claim_package,
        }))
        .expect("verification response");

    assert_eq!(noncanonical_claim_result["verifierStatus"], "refused");
    assert_eq!(
        noncanonical_claim_result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );

    let mut low_degree_shape_package = package;
    let trustee_roster_position = low_degree_shape_package["trusteeEvaluationKeyProofs"]
        ["proofRecords"][0]["trusteeRosterPosition"]
        .as_u64()
        .expect("trustee roster position");
    let round_one_aggregate_diagonals =
        round_one_aggregate_diagonals_from_fixture_package(&low_degree_shape_package, None);
    let statement =
        trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
            setup_package: &low_degree_shape_package,
            transported_key_switch_component_material: None,
            transported_constant_commitments: &BTreeMap::new(),
            round_one_aggregate_diagonals_by_level: &round_one_aggregate_diagonals,
            trustee_roster_position,
        })
        .expect("trustee evaluation-key statement");
    let total_error_column_count = statement.keys.iter().map(|key| key.level + 1).sum();
    let linkage_commitment_count = statement
        .same_secret_linkage
        .as_ref()
        .expect("trustee evaluation-key same-secret linkage")
        .commitments
        .len();
    mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
        &mut low_degree_shape_package,
        |proof_bytes| {
            set_first_limb_low_degree_fold_count_to_wrong_value(
                proof_bytes,
                statement.ring_degree,
                total_error_column_count,
                linkage_commitment_count,
            );
        },
    );
    let low_degree_shape_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": low_degree_shape_package,
        }))
        .expect("verification response");

    assert_eq!(low_degree_shape_result["verifierStatus"], "refused");
    assert_eq!(
        low_degree_shape_result["refusedObjects"][0]["reasonCode"],
        "trusteeEvaluationKeyProofVerificationFailed"
    );
    assert!(
        low_degree_shape_result["refusedObjects"][0]["message"]
            .as_str()
            .expect("refusal message")
            .contains("low-degree committed fold count does not match the statement")
    );
    assert!(low_degree_shape_result["acceptedSetupHandoff"].is_null());
}

fn mutate_first_trustee_evaluation_key_proof_bytes_and_rebind(
    package: &mut serde_json::Value,
    mutate_proof_bytes: impl FnOnce(&mut [u8]),
) {
    let proof_record = &mut package["trusteeEvaluationKeyProofs"]["proofRecords"][0];
    let proof_bytes_hex = proof_record["proofBytesHex"]
        .as_str()
        .expect("embedded trustee proof bytes")
        .to_string();
    let mut proof_bytes = decode_hex(&proof_bytes_hex).expect("trustee proof bytes");
    mutate_proof_bytes(&mut proof_bytes);
    proof_record["proofBytesHex"] = serde_json::json!(to_hex(&proof_bytes));
    proof_record["proofBytesHash"] =
        serde_json::json!(trustee_evaluation_key_proof_bytes_hash(&proof_bytes));
    proof_record["proofSizeBytes"] = serde_json::json!(proof_bytes.len());
    rebind_trustee_evaluation_key_proof_record_root(package, 0);
    rebind_trustee_evaluation_key_proof_set_root(package);
    rebind_setup_key_correctness_certificate(package);
    rebind_collective_setup_package_hash(package);
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_round_two_records_with_substituted_aggregate_source_cannot_reprove() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_round_two_records_with_substituted_aggregate_source_cannot_reprove",
    );
    // A trustee whose round-two share multiplies a substituted aggregate
    // cannot generate a verifying proof: the statement carries the aggregate
    // recomputed from the round-one records, so the honest witness fails the
    // batched relation at proving time.
    let package = evaluation_key_proof_container_bearing_collective_setup_package_ref();
    let honest_aggregates = round_one_aggregate_diagonals_from_fixture_package(package, None);
    let scheduled_level = *honest_aggregates
        .keys()
        .next()
        .expect("scheduled relinearization level");
    let mut substituted_aggregates = honest_aggregates
        .get(&scheduled_level)
        .expect("aggregate diagonals")
        .clone();
    substituted_aggregates[0][0] = (substituted_aggregates[0][0] + 1) % DATA_PRIMES[0];
    let ring_degree =
        same_secret_constant_commitments_from_fixture_package(package, 0)[0].ring_degree;
    let substituted_source = relinearization_round_two_source_by_digit_for_fixture(
        0,
        ring_degree,
        &substituted_aggregates,
    );
    let schedule = &package["evaluatorKeySchedule"];
    let key_switch_seed_hex =
        relinearization_key_switch_seed_for_test(schedule, "round-two", scheduled_level);
    let substituted_material = evaluation_key_share_fixture_material(
        EvaluationKeyShareProofFamily::Relinearization,
        0,
        scheduled_level,
        None,
        ring_degree,
        &key_switch_seed_hex,
        Some(&substituted_source),
    );

    let mut tampered_package = package.clone();
    let record = &mut tampered_package["relinearizationKeyShareRounds"]["roundTwoRecords"][0];
    assert_eq!(record["trusteeRosterPosition"], 0);
    record["keySwitchComponentVectorRoot"] =
        serde_json::json!(substituted_material.component_vector_root.clone());
    record["roundTwoShareRoot"] =
        serde_json::json!(substituted_material.component_vector_root.clone());
    record["keySwitchComponentVectors"] =
        serde_json::json!(substituted_material.component_vector_entries.clone());

    let aggregates = round_one_aggregate_diagonals_from_fixture_package(&tampered_package, None);
    let statement =
        trustee_evaluation_key_statement_from_package(&TrusteeEvaluationKeyStatementInputs {
            setup_package: &tampered_package,
            transported_key_switch_component_material: None,
            transported_constant_commitments: &BTreeMap::new(),
            round_one_aggregate_diagonals_by_level: &aggregates,
            trustee_roster_position: 0,
        })
        .expect("statement over substituted round-two share");
    let witness = trustee_evaluation_key_witness_for_fixture(0, ring_degree, &statement);
    let proof_randomness_seed_hex = derive_protocol_hash(
        "TrusteeEvaluationKeyProofRandomness",
        &serde_json::json!({
            "fixture": "substituted-aggregate-reprove",
            "trusteeRosterPosition": 0,
        }),
    )
    .expect("proof randomness seed");

    let error = match prove_evaluation_key_share(&statement, &witness, &proof_randomness_seed_hex) {
        Ok(_) => panic!("substituted aggregate source must not prove"),
        Err(error) => error,
    };

    assert!(
        error.message.contains("witness does not satisfy") || error.message.contains("sumcheck"),
        "{}",
        error.message
    );
}
