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
fn setup_proof_accounting_certificate_accepts_claim_theorem_accounting() {
    let certificate =
        setup_proof_accounting_certificate_value().expect("setup proof accounting certificate");
    let proof_family_accounting = certificate["proofFamilyAccounting"]
        .as_array()
        .expect("proof family accounting");
    let proof_families = certificate["proofFamilies"]
        .as_array()
        .expect("proof family list");

    assert_eq!(proof_family_accounting.len(), 4);
    assert_eq!(proof_families.len(), 4);
    for expected_family in [
        "same-secret-linkage-anchor",
        "public-key-share",
        "vss-opening-carry",
        "trustee-evaluation-key",
    ] {
        assert!(
            proof_families
                .iter()
                .any(|proof_family| proof_family == expected_family),
            "setup proof accounting certificate must list {expected_family}"
        );
    }
    assert_eq!(
        proof_family_accounting[0]["proofFamily"],
        "vss-opening-carry"
    );
    assert_eq!(
        proof_family_accounting[0]["verifierClosedStatus"],
        "statement-rebuild-and-succinct-argument-checks-verifier-closed"
    );
    assert_eq!(
        proof_family_accounting[0]["accountingStatus"],
        "succinct-private-vss-share-theorem-accounting-accepted"
    );
    assert!(
        proof_family_accounting[0]["verifierClosedChecks"]
            .as_array()
            .expect("private VSS verifier-closed checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("lifted share relation")))
    );
    assert_eq!(
        proof_family_accounting[0]["claimAccounting"]["accountingObject"],
        "SuccinctPrivateVssShareAccounting"
    );
    assert_eq!(
        proof_family_accounting[0]["claimAccounting"]["accountingHash"],
        certificate["privateVssShareProofAccountingHash"]
    );
    assert_eq!(
        certificate["privateVssShareProofAccounting"]["objectType"],
        "SuccinctPrivateVssShareAccounting"
    );
    let private_vss_smudging =
        &certificate["privateVssShareProofAccounting"]["zeroKnowledge"]["smudgingBudget"];
    assert_eq!(
        private_vss_smudging["acceptedForBoundedLeakagePrototype"],
        true
    );
    assert_eq!(
        private_vss_smudging["acceptedFor128BitZeroKnowledge"],
        false
    );
    let private_vss_clear_claim_bound_bits = private_vss_smudging["clearClaimBoundBits"]
        .as_i64()
        .expect("private VSS clear claim bound bits");
    let private_vss_per_claim_leakage = private_vss_smudging["perClaimStatisticalDistanceLog2"]
        .as_i64()
        .expect("private VSS per-claim leakage");
    assert_eq!(
        private_vss_per_claim_leakage,
        private_vss_clear_claim_bound_bits - 92
    );
    assert!(
        private_vss_per_claim_leakage > -68,
        "private VSS must not inherit the evaluation-key smudging budget"
    );
    assert!(
        private_vss_smudging["totalLeakageLog2Approximate"]
            .as_i64()
            .expect("private VSS total leakage")
            > -50,
        "private VSS total leakage must disclose the wider family bound"
    );
    assert!(
        private_vss_smudging["leakageStatement"]
            .as_str()
            .is_some_and(|text| text.contains("minus twenty-two"))
    );

    // The same-secret linkage anchor carries its accepted succinct accounting:
    // the row binds the anchor accounting object with every theorem row closed
    // under the explicitly named FRI conjecture.
    let anchor_family = &proof_family_accounting[1];
    assert_eq!(anchor_family["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(
        anchor_family["accountingStatus"],
        "succinct-same-secret-linkage-anchor-theorem-accounting-accepted"
    );
    assert_eq!(
        anchor_family["claimAccounting"]["accountingHash"],
        certificate["sameSecretLinkageAnchorProofAccountingHash"]
    );
    assert!(
        anchor_family["claimAccounting"]["claimBoundary"]
            .as_str()
            .is_some_and(|text| text.contains("named FRI conjecture"))
    );
    assert_eq!(
        certificate["sameSecretLinkageAnchorProofAccounting"]["objectType"],
        "SuccinctSameSecretLinkageAnchorAccounting"
    );

    let public_key_family = &proof_family_accounting[2];
    assert_eq!(public_key_family["proofFamily"], "public-key-share");
    assert_eq!(
        public_key_family["accountingStatus"],
        "succinct-public-key-share-theorem-accounting-accepted"
    );
    assert_eq!(
        public_key_family["claimAccounting"]["accountingHash"],
        certificate["publicKeyShareProofAccountingHash"]
    );
    assert_eq!(
        certificate["publicKeyShareProofAccounting"]["objectType"],
        "SuccinctPublicKeyShareAccounting"
    );
    assert!(
        public_key_family["verifierClosedChecks"]
            .as_array()
            .expect("public-key verifier checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("limb-zero"))),
        "public-key setup proof accounting must state the limb-zero linkage dependency"
    );

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
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["lowDegreeSoundness"]["acceptedUnderNamedFriConjecture"],
        true
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["lowDegreeSoundness"]["acceptedUnderProvenFallback"],
        false
    );
    assert!(
        certificate["trusteeEvaluationKeyProofAccounting"]["fiatShamir"]
            ["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("effective soundness bits")
            >= 128
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["fiatShamir"]["qromAccepted"],
        false
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["zeroKnowledge"]["smudgingBudget"]["acceptedFor128BitZeroKnowledge"],
        false
    );
    assert_eq!(
        certificate["certificateStatus"],
        "succinct-setup-proof-family-accounting-accepted-achieved-qrom-recorded"
    );

    let succinct_transport_accounting = certificate["succinctTransportAccounting"]
        .as_object()
        .expect("succinct transport accounting");
    assert_eq!(
        succinct_transport_accounting["accountingStatus"],
        "succinct-proof-material-roots-and-transport-binding-accepted"
    );
    assert_eq!(
        succinct_transport_accounting["closedProofFamilies"]
            .as_array()
            .expect("closed succinct transport proof families")
            .len(),
        4
    );
    assert!(
        succinct_transport_accounting["closedVerifierChecks"]
            .as_array()
            .expect("closed succinct transport verifier checks")
            .iter()
            .any(|check| check
                .as_str()
                .is_some_and(|text| text.contains("no relation-commitment or tbox metadata")))
    );

    let fiat_shamir_accounting = certificate["fiatShamirTranscriptAccounting"]
        .as_object()
        .expect("Fiat-Shamir transcript accounting");
    assert_eq!(
        fiat_shamir_accounting["accountingStatus"],
        "succinct-family-fiat-shamir-accounting-bound-with-achieved-qrom-recorded"
    );
    assert_eq!(
        fiat_shamir_accounting["qromReductionStatus"],
        "computed-cms19-state-restoration-achieved-level-recorded-per-family"
    );
    assert_eq!(fiat_shamir_accounting["qromReductionLossComputed"], true);
    assert_eq!(fiat_shamir_accounting["qromAccepted"], false);
    assert_eq!(
        fiat_shamir_accounting["meetsConventional128BitQuantumBar"],
        false
    );
    assert_eq!(
        fiat_shamir_accounting["achievedQuantumSoundnessAfterInstanceUnionBitsApproximate"],
        70
    );
    assert_eq!(
        fiat_shamir_accounting["familyAccountingHashes"]["privateVssShare"],
        proof_family_accounting[0]["claimAccounting"]["accountingHash"]
    );

    let succinct_leakage_accounting = certificate["succinctLeakageAccounting"]
        .as_object()
        .expect("succinct leakage accounting");
    assert_eq!(
        succinct_leakage_accounting["accountingStatus"],
        "succinct-family-leakage-scope-bound-per-family"
    );
    assert!(
        succinct_leakage_accounting["zeroKnowledgeScope"]
            .as_str()
            .is_some_and(|text| text.contains("bounded-leakage"))
    );
    let proof_theorem_accounting = certificate["proofTheoremAccounting"]
        .as_object()
        .expect("proof theorem accounting");
    assert_eq!(
        proof_theorem_accounting["accountingStatus"],
        "succinct-setup-proof-family-accounting-accepted-achieved-qrom-recorded"
    );
    assert_eq!(
        proof_theorem_accounting["familyAccounting"]["privateVssShare"]["objectType"],
        "SuccinctPrivateVssShareAccounting"
    );
    assert!(
        proof_theorem_accounting["proofFamilies"]
            .as_array()
            .expect("proof theorem families")
            .iter()
            .any(|proof_family| proof_family == "vss-opening-carry")
    );
}

#[test]
fn collective_setup_verifier_refuses_duplicate_current_proof_accounting_row() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_duplicate_current_proof_accounting_row",
    );
    let mut package = minimal_collective_setup_package();
    let duplicate_public_key_accounting_row =
        package["setupProofAccountingCertificate"]["proofFamilyAccounting"][2].clone();
    package["setupProofAccountingCertificate"]["proofFamilies"]
        .as_array_mut()
        .expect("proof family list")
        .push(serde_json::json!("public-key-share"));
    package["setupProofAccountingCertificate"]["proofFamilyAccounting"]
        .as_array_mut()
        .expect("proof family accounting")
        .push(duplicate_public_key_accounting_row);
    rebind_setup_proof_accounting_certificate_hash(&mut package);
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
    assert!(result["acceptedSetupHandoff"].is_null());
}

#[test]
fn collective_setup_verifier_refuses_upgraded_non_claim_proof_model_rows() {
    // These rows must stay false and the verifier must reject any upgrade to
    // true: the setup proofs record achieved-level QROM metadata, but not QROM
    // strength or 128-bit zero-knowledge, so claiming otherwise would overstate
    // the closed claim boundary.
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_upgraded_non_claim_proof_model_rows",
    );

    let model_row_mutations: [fn(&mut serde_json::Value); 5] = [
        |package| {
            package["setupProofAccountingCertificate"]["fiatShamirTranscriptAccounting"]["qromReductionStatus"] =
                serde_json::json!("qrom-reduction-loss-accepted-for-final-claim");
        },
        |package| {
            package["setupProofAccountingCertificate"]["fiatShamirTranscriptAccounting"]["qromAccepted"] =
                serde_json::json!(true);
        },
        |package| {
            package["setupProofAccountingCertificate"]["succinctLeakageAccounting"]["zeroKnowledgeScope"] =
                serde_json::json!("128-bit zero-knowledge accepted for every setup proof family");
        },
        |package| {
            package["setupProofAccountingCertificate"]["trusteeEvaluationKeyProofAccounting"]["zeroKnowledge"]
                ["smudgingBudget"]["acceptedFor128BitZeroKnowledge"] = serde_json::json!(true);
        },
        |package| {
            package["setupProofAccountingCertificate"]["privateVssShareProofAccounting"]["zeroKnowledge"]
                ["smudgingBudget"]["acceptedFor128BitZeroKnowledge"] = serde_json::json!(true);
        },
    ];

    for mutate_model_row in model_row_mutations {
        let mut package = minimal_collective_setup_package();
        mutate_model_row(&mut package);
        rebind_setup_proof_accounting_certificate_hash(&mut package);
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
        assert!(result["acceptedSetupHandoff"].is_null());
    }
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
    rebind_setup_assembly_provenance_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"], "pending",
        "unexpected verification result: {result:#}"
    );
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
        "publicKeyShareSuccinctProofs": {
            "publicKeyShareSuccinctProofSetRoot": valid_hash('b'),
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
        "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-succinct-proof-roots"
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
    rebind_setup_assembly_provenance_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"], "refused",
        "unexpected verification result: {result:#}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "setupKeyCorrectnessCertificatePayloadMismatch",
        "unexpected verification result: {result:#}"
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
    rebind_setup_assembly_provenance_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"], "refused",
        "unexpected verification result: {result:#}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"], "setupKeyCorrectnessCertificateHashMismatch",
        "unexpected verification result: {result:#}"
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
    rebind_setup_assembly_provenance_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(
        result["verifierStatus"], "refused",
        "unexpected verification result: {result:#}"
    );
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupKeyCorrectnessPackageCertificateHashMismatch",
        "unexpected verification result: {result:#}"
    );
}

#[test]
fn collective_setup_verifier_requires_setup_assembly_provenance_certificate() {
    let mut package = minimal_collective_setup_package();
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupAssemblyProvenanceCertificate");
    package
        .as_object_mut()
        .expect("setup package")
        .remove("setupAssemblyProvenanceCertificateHash");
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
            .any(|object| object == "setupAssemblyProvenanceCertificate")
    );
}

#[test]
fn setup_assembly_provenance_certificate_records_accepted_source_boundary() {
    let package = minimal_collective_setup_package();
    let certificate = setup_assembly_provenance_certificate_value(&package)
        .expect("setup assembly provenance certificate");

    assert_eq!(
        certificate["objectType"],
        "SetupAssemblyProvenanceCertificate"
    );
    assert_eq!(
        certificate["assemblySource"],
        "integrated-full-roster-setup-package-assembly"
    );
    assert_eq!(
        certificate["sourceBoundary"]["acceptedHandoffSource"],
        "accepted-setup-verifier-after-package-hash-certificate-and-final-object-gates"
    );
    assert_eq!(
        certificate["sourceBoundary"]["developmentAssemblyAcceptedAsClaimSource"],
        false
    );
    assert_eq!(
        certificate["sourceBoundary"]["helperAssemblyAcceptedAsClaimSource"],
        false
    );
    assert_eq!(
        certificate["rootBindings"]["commonRandomnessRoot"],
        package["commonRandomness"]["commonRandomnessRoot"]
    );
    assert!(
        certificate["rootBindings"]["phaseTranscriptRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
    assert_eq!(
        certificate["claimBoundary"],
        "accepted setup handoff construction is sourced from this verifier-recomputed package provenance certificate, not from development assembly or helper paths"
    );
}

#[test]
fn collective_setup_verifier_checks_setup_assembly_provenance_certificate() {
    let mut package = minimal_collective_setup_package();
    package["setupAssemblyProvenanceCertificate"]["claimBoundary"] =
        serde_json::json!("development-assembly-accepted");
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupAssemblyProvenanceCertificatePayloadMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_setup_assembly_provenance_certificate_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["setupAssemblyProvenanceCertificate"]["setupAssemblyProvenanceCertificateHash"] =
        serde_json::json!(valid_hash('d'));
    package["setupAssemblyProvenanceCertificateHash"] = serde_json::json!(valid_hash('d'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupAssemblyProvenanceCertificateHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_setup_assembly_provenance_package_hash_drift() {
    let mut package = minimal_collective_setup_package();
    package["setupAssemblyProvenanceCertificateHash"] = serde_json::json!(valid_hash('e'));
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "setupAssemblyProvenancePackageCertificateHashMismatch"
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
        certificate["dependencyHashes"]["setupAssemblyProvenanceCertificateHash"],
        package["setupAssemblyProvenanceCertificateHash"]
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
