use super::*;

#[test]
fn collective_setup_verifier_refuses_wrong_q_share_prime_list() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_wrong_q_share_prime_list");
    let mut package = minimal_collective_setup_package();
    package["qShare"]["primes"][0] = serde_json::json!(65_537);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(result["refusedObjects"][0]["reasonCode"], "qShareMismatch");
}

#[test]
fn collective_setup_verifier_refuses_malformed_commitment_security_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_commitment_security_certificate",
    );
    let mut package = minimal_collective_setup_package();
    package["setupCommitmentSecurityCertificate"]["aggregateOpeningBounds"]["thresholdShareOpeningInfinityBound"] =
        serde_json::json!(11_109_u64);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "commitmentSecurityCertificatePayloadMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_commitment_security_certificate_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_commitment_security_certificate_hash_drift",
    );
    let mut package = minimal_collective_setup_package();
    package["setupCommitmentSecurityCertificateHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "commitmentSecurityPackageCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_setup_proof_accounting_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_setup_proof_accounting_certificate",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificate"]["challengeAccounting"]["qromStatus"] =
        serde_json::json!("externally-reviewed");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingCertificatePayloadMismatch"
    );
}

#[test]
fn setup_proof_accounting_certificate_accepts_claim_theorem_accounting() {
    let certificate =
        setup_proof_accounting_certificate_value().expect("setup proof accounting certificate");
    let proof_family_accounting = certificate["proofFamilyAccounting"]
        .as_array()
        .expect("proof family accounting");

    assert_eq!(proof_family_accounting.len(), 4);
    assert_eq!(
        proof_family_accounting[0]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        proof_family_accounting[0]["verifierClosedStatus"],
        "relation-transcript-and-bound-checks-verifier-closed"
    );
    assert_eq!(
        proof_family_accounting[0]["accountingStatus"],
        "repo-owned-soundness-zero-knowledge-and-qrom-accounting-accepted"
    );
    assert!(
        proof_family_accounting[2]["verifierClosedChecks"]
            .as_array()
            .expect("public-key verifier-closed checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("lifted public-key equality")))
    );
    assert!(proof_family_accounting[..3].iter().all(|family| {
        family["claimAccounting"]["qrom"]
            .as_str()
            .is_some_and(|text| text.contains("Fiat-Shamir reduction accounting is accepted"))
    }));

    // The trustee evaluation-key family carries its accepted accounting: the
    // row binds the succinct accounting object with every theorem row closed
    // under the explicitly named FRI conjecture.
    let trustee_family = &proof_family_accounting[3];
    assert_eq!(trustee_family["proofFamily"], "trustee-evaluation-key");
    assert_eq!(
        trustee_family["accountingStatus"],
        "succinct-trustee-evaluation-key-theorem-accounting-accepted"
    );
    assert_eq!(
        trustee_family["claimAccounting"]["accountingHash"],
        certificate["trusteeEvaluationKeyProofAccountingHash"]
    );
    assert!(
        trustee_family["claimAccounting"]["claimBoundary"]
            .as_str()
            .is_some_and(|text| text.contains("named FRI conjecture"))
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["objectType"],
        "SuccinctEvaluationKeyProofAccounting"
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["lowDegreeSoundness"]["accepted"],
        true
    );
    assert!(
        certificate["trusteeEvaluationKeyProofAccounting"]["fiatShamir"]
            ["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("effective soundness bits")
            >= 128
    );
    assert_eq!(
        certificate["certificateStatus"],
        "lnp-and-trustee-evaluation-key-family-accounting-accepted"
    );

    let tbox_accounting = certificate["tboxAccounting"]
        .as_object()
        .expect("tbox accounting");
    assert_eq!(
        tbox_accounting["accountingStatus"],
        "generated-lower-protocol-tbox-profile-verifier-and-prover-closed"
    );
    assert_eq!(
        tbox_accounting["closedProofFamilies"]
            .as_array()
            .expect("closed tbox proof families")
            .len(),
        3
    );
    assert!(
        tbox_accounting["closedVerifierChecks"]
            .as_array()
            .expect("closed tbox verifier checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("generated lower-protocol tbox suffix")))
    );

    let fiat_shamir_accounting = certificate["fiatShamirTranscriptAccounting"]
        .as_object()
        .expect("Fiat-Shamir transcript accounting");
    assert_eq!(
        fiat_shamir_accounting["accountingStatus"],
        "fiat-shamir-transcript-domain-and-challenge-input-accounting-closed"
    );
    assert_eq!(
        fiat_shamir_accounting["qromReductionStatus"],
        "repo-owned-qrom-reduction-theorem-accepted-for-setup-proof-claim"
    );
    assert!(
        fiat_shamir_accounting["challengeStages"]
            .as_array()
            .expect("Fiat-Shamir challenge stages")
            .iter()
            .any(|stage| stage["stageId"] == "scalar-relation-challenge")
    );
    assert!(
        fiat_shamir_accounting["referenceRows"]
            .as_array()
            .expect("Fiat-Shamir reference rows")
            .iter()
            .any(|reference| reference["document"]
                .as_str()
                .is_some_and(|text| text.starts_with("DFM20_")))
    );

    let response_masking_accounting = certificate["responseMaskingAccounting"]
        .as_object()
        .expect("response masking accounting");
    assert_eq!(
        response_masking_accounting["accountingStatus"],
        "response-mask-bounds-strengthened-verifier-bound-and-zk-accounting-accepted"
    );
    assert_eq!(
        response_masking_accounting["encodingConstraints"]["relationCommitmentEncoding"],
        "public-key lifted relation commitments use fixed-width signed 32-byte little-endian big-integer coefficients; response vectors remain signed i128"
    );
    let response_families = response_masking_accounting["families"]
        .as_array()
        .expect("response masking families");
    assert_eq!(response_families.len(), 3);
    assert_eq!(
        response_families[0]["fullWidthCoefficientMaskingStatus"],
        "centered-signed-private-vss-message-response-masking-verifier-bound-and-simulator-accounting-accepted"
    );
    assert_eq!(
        response_families[0]["commitmentNoWrapStatus"],
        "three-limb-big-int-no-wrap-bound-recorded"
    );
    assert_eq!(
        response_families[0]["responseProfiles"][0]["maskRandomBits"],
        112
    );
    assert!(
        response_families[0]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("private VSS coefficient masking slack")
            > 0
    );
    assert_eq!(
        response_families[1]["responseProfiles"][0]["maskRandomBits"],
        80
    );
    assert!(
        response_families[1]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("same-secret secret masking slack")
            > 0
    );
    assert_eq!(
        response_families[2]["responseProfiles"][0]["maskRandomBits"],
        80
    );
    assert!(
        response_families[2]["responseProfiles"][0]["maskingSlackBits"]
            .as_i64()
            .expect("public-key secret masking slack")
            > 0
    );

    let proof_theorem_accounting = certificate["proofTheoremAccounting"]
        .as_object()
        .expect("proof theorem accounting");
    assert_eq!(
        proof_theorem_accounting["accountingStatus"],
        "repo-owned-setup-proof-soundness-zero-knowledge-and-qrom-accounting-accepted"
    );
    assert_eq!(
        proof_theorem_accounting["qromReductionAccounting"]["compositionStatus"],
        "accepted-for-fixed-three-family-two-stage-setup-profile"
    );
    assert!(
        proof_theorem_accounting["referenceRows"]
            .as_array()
            .expect("proof theorem reference rows")
            .iter()
            .any(|reference| reference["document"]
                .as_str()
                .is_some_and(|text| text.starts_with("LNP22_")))
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_challenge_audit_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_challenge_audit_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificate"]["challengeAccounting"]["challengeSpaceAuditHash"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingCertificatePayloadMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_accounting_certificate_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_proof_accounting_certificate_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupProofAccountingCertificateHash"] = serde_json::json!(valid_hash('6'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupProofAccountingPackageCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_checks_he_security_certificate() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_checks_he_security_certificate");
    let mut package = minimal_collective_setup_package();
    package["heSecurityCertificate"]["assessedRing"]["largestExposedBasisClass"] =
        serde_json::json!("Q_extended");
    rebind_collective_he_security_certificate_hash(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "heSecurityCertificateMismatch"
    );
}

#[test]
fn he_security_certificate_accepts_direct_setup_evaluator_parameter_boundary() {
    let certificate = accepted_he_security_certificate_value().expect("HE security certificate");

    assert_eq!(
        certificate["parameterBoundary"]["certificateStatus"],
        "accepted-for-direct-setup-and-evaluator-HE-parameter-boundary"
    );
    assert_eq!(certificate["acceptedForDirectEvaluatorReplay"], true);
    assert_eq!(certificate["acceptedForTargetDecryption"], false);
    assert_eq!(
        certificate["targetDecryptionStatus"]["targetDecryptionReadiness"],
        "refused-until-q-target-certificate-closes"
    );
    assert_eq!(
        certificate["errorDistribution"]["certificateStatus"],
        "accepted-for-direct-evaluator-replay-HE-parameter-boundary"
    );
    assert!(
        certificate["statusLabels"]
            .as_array()
            .expect("HE certificate status labels")
            .iter()
            .any(|label| label
                .as_str()
                .is_some_and(|text| text == "DirectSetupEvaluatorHeParameterBoundaryAccepted"))
    );
}

#[test]
fn collective_setup_verifier_refuses_he_security_certificate_hash_drift() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_he_security_certificate_hash_drift",
    );
    let mut package = minimal_collective_setup_package();
    package["heSecurityCertificateHash"] = serde_json::json!(valid_hash('7'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "packageHeSecurityCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_requires_setup_key_correctness_certificate_for_evaluation_keys()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_requires_setup_key_correctness_certificate_for_evaluation_keys",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupKeyCorrectnessCertificate");
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupKeyCorrectnessCertificateHash");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert!(
        result["missingObjects"]
            .as_array()
            .expect("pending objects")
            .iter()
            .any(|object| object == "setupKeyCorrectnessCertificate")
    );
}

#[test]
fn setup_key_correctness_certificate_binds_accepted_theorem_statement() {
    let package = serde_json::json!({
        "setupContext": {
            "ceremonyId": "ceremony-main",
            "manifestHash": valid_hash('1'),
            "rosterHash": valid_hash('2'),
            "setupProfileHash": valid_hash('3'),
            "qShareHash": valid_hash('4'),
            "carryAwareVssShareRelationProfileHash": valid_hash('5'),
            "commitmentProfileHash": valid_hash('6'),
            "setupEpoch": "setup-epoch-1",
        },
        "collectivePublicKey": {
            "collectivePublicKeyRoot": valid_hash('7'),
        },
        "publicKeyShares": {
            "publicKeyShareSetRoot": valid_hash('8'),
        },
        "publicKeyShareProofs": {
            "publicKeyShareProofSetRoot": valid_hash('9'),
        },
        "publicKeyShareMaterial": {
            "publicKeyShareMaterialSetRoot": valid_hash('a'),
        },
        "publicKeyShareLnpProofs": {
            "publicKeyShareLnpProofSetRoot": valid_hash('b'),
        },
        "evaluationKeys": {
            "evaluationKeySetHash": valid_hash('c'),
        },
        "evaluatorKeySchedule": {
            "evaluatorKeyScheduleRoot": valid_hash('d'),
            "requiredGaloisSetHash": valid_hash('e'),
        },
        "relinearizationKeyShareRounds": {
            "relinearizationKeyShareRoundsRoot": valid_hash('f'),
        },
        "galoisKeyShareBatches": [
            {
                "trusteeIdentity": "trustee-0",
                "trusteeRosterPosition": 0,
                "galoisKeyShareBatchRoot": valid_hash('0'),
            }
        ],
        "setupProofAccountingCertificateHash": valid_hash('1'),
        "heSecurityCertificateHash": valid_hash('2'),
    });

    let certificate = setup_key_correctness_certificate_value(&package)
        .expect("setup key correctness certificate");

    assert_eq!(
        certificate["keyCorrectnessTheorem"]["theoremStatus"],
        "repo-owned-key-correctness-theorem-accepted-for-verifier-recomputed-roots"
    );
    assert_eq!(
        certificate["collectivePublicKey"]["status"],
        "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-LNP-proof-roots"
    );
    assert_eq!(
        certificate["publicEvaluationKeys"]["status"],
        "public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records"
    );
    assert!(
        certificate["keyCorrectnessTheorem"]["checkedByVerifier"]
            .as_array()
            .expect("checked theorem clauses")
            .iter()
            .any(|clause| {
                clause
                    == "transported public evaluation-key runtime material is verified against evaluationKeys when supplied"
            })
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_checks_setup_key_correctness_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_checks_setup_key_correctness_certificate",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificate"]["claimBoundary"] =
        serde_json::json!("weakened-key-correctness-claim");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessCertificatePayloadMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_certificate_hash_drift()
 {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_certificate_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificate"]["setupKeyCorrectnessCertificateHash"] =
        serde_json::json!(valid_hash('8'));
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('8'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessCertificateHashMismatch"
    );
}

#[test]
#[ignore = "heavy accepted setup test"]
fn heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_package_hash_drift()
{
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "heavy_accepted_setup_collective_setup_verifier_refuses_setup_key_correctness_package_hash_drift",
    );
    let mut package = evaluation_key_proof_container_bearing_collective_setup_package();
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('9'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessPackageCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_requires_active_static_setup_theorem_certificate() {
    let mut package = minimal_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("activeStaticSetupTheoremCertificate");
    package
        .as_object_mut()
        .expect("setup package")
        .remove("activeStaticSetupTheoremCertificateHash");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "pending");
    assert!(
        result["missingObjects"]
            .as_array()
            .expect("pending objects")
            .iter()
            .any(|object| object == "activeStaticSetupTheoremCertificate")
    );
}

#[test]
fn active_static_setup_theorem_certificate_records_accepted_claim_boundary() {
    let mut package = minimal_collective_setup_package();
    package["setupKeyCorrectnessCertificateHash"] = serde_json::json!(valid_hash('c'));
    let certificate = active_static_setup_theorem_certificate_value(&package)
        .expect("active-static setup theorem certificate");

    assert_eq!(
        certificate["objectType"],
        "ActiveStaticSetupTheoremCertificate"
    );
    assert_eq!(
        certificate["adversaryModel"]["corruptionTiming"],
        "active-static"
    );
    assert_eq!(certificate["livenessModel"]["model"], "secure-with-abort");
    assert_eq!(
        certificate["dependencyHashes"]["setupKeyCorrectnessCertificateHash"],
        package["setupKeyCorrectnessCertificateHash"]
    );
    assert_eq!(
        certificate["claimBoundary"]["certificateStatus"],
        "active-static-secure-with-abort-theorem-accepted"
    );
    let remaining_dependencies = certificate["claimBoundary"]["remainingDependencies"]
        .as_array()
        .expect("remaining theorem dependencies");
    assert!(remaining_dependencies.is_empty());
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("AB-DLOP/LNP soundness"))
    }));
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("Fiat-Shamir/QROM"))
    }));
    assert!(remaining_dependencies.iter().all(|dependency| {
        dependency
            .as_str()
            .is_some_and(|text| !text.contains("tbox"))
    }));
    assert_eq!(
        certificate["claimBoundary"]["completionBoundary"],
        "external validation, independent audit, and third-party proof review are not setup completion prerequisites"
    );
}

#[test]
fn collective_setup_verifier_checks_active_static_setup_theorem_certificate() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificate"]["claimBoundary"]["completionBoundary"] =
        serde_json::json!("external-review-required");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremCertificatePayloadMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_active_static_setup_theorem_certificate_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificate"]["activeStaticSetupTheoremCertificateHash"] =
        serde_json::json!(valid_hash('a'));
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(valid_hash('a'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_active_static_setup_theorem_package_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(valid_hash('b'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "activeStaticSetupTheoremPackageCertificateHashMismatch"
    );
}
