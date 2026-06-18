use super::*;
use crate::bgv::profile::{data_basis_modulus_bits, extended_basis_modulus_bits};

#[test]
fn collective_setup_verifier_refuses_wrong_q_share_prime_list() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_refuses_wrong_q_share_prime_list");
    let mut package = minimal_collective_setup_package();
    package["qShare"]["primes"][0] = serde_json::json!(65_537);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_setup_package(package);

    assert_eq!(result["verifierStatus"], "outsideProfile");
    assert_eq!(result["refusedObjects"][0]["reasonCode"], "qShareMismatch");
}

#[test]
fn collective_setup_verifier_refuses_malformed_commitment_security_certificate() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_commitment_security_certificate",
    );
    assert_minimal_collective_setup_package_refused(
        "malformed commitment security certificate opening bound",
        |package| {
            package["setupCommitmentSecurityCertificate"]["aggregateOpeningBounds"]["thresholdShareOpeningInfinityBound"] =
                serde_json::json!(11_109_u64);
        },
        "commitmentSecurityCertificatePayloadMismatch",
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
    // Each proof family row now binds its succinct accounting object only
    // through the recomputed accounting hash. The private VSS row hash must
    // match the hash the Fiat-Shamir transcript accounting records for the
    // same family, so the row and the transcript object cannot drift apart.
    assert_eq!(
        proof_family_accounting[0]["claimAccounting"]["accountingHash"],
        certificate["fiatShamirTranscriptAccounting"]["familyAccountingHashes"]["privateVssShare"]
    );

    // The same-secret linkage anchor row binds the anchor accounting hash that
    // the certificate also surfaces as a top-level dependency hash.
    let anchor_family = &proof_family_accounting[1];
    assert_eq!(anchor_family["proofFamily"], "same-secret-linkage-anchor");
    assert_eq!(
        anchor_family["claimAccounting"]["accountingHash"],
        certificate["sameSecretLinkageAnchorProofAccountingHash"]
    );
    assert_eq!(
        certificate["sameSecretLinkageAnchorProofAccounting"]["objectType"],
        "SuccinctSameSecretLinkageAnchorAccounting"
    );

    let public_key_family = &proof_family_accounting[2];
    assert_eq!(public_key_family["proofFamily"], "public-key-share");
    assert_eq!(
        public_key_family["claimAccounting"]["accountingHash"],
        certificate["publicKeyShareProofAccountingHash"]
    );
    assert_eq!(
        certificate["publicKeyShareProofAccounting"]["objectType"],
        "SuccinctPublicKeyShareAccounting"
    );

    // The trustee evaluation-key row binds the evaluation-key accounting hash
    // that the certificate also surfaces as a top-level dependency hash.
    let trustee_family = &proof_family_accounting[3];
    assert_eq!(trustee_family["proofFamily"], "trustee-evaluation-key");
    assert_eq!(
        trustee_family["claimAccounting"]["accountingHash"],
        certificate["trusteeEvaluationKeyProofAccountingHash"]
    );
    assert_eq!(
        certificate["trusteeEvaluationKeyProofAccounting"]["objectType"],
        "SuccinctEvaluationKeyProofAccounting"
    );
    // The recomputed effective soundness, not a self-attested verdict flag, is
    // what the bound accounting object must carry: it stays at or above the
    // 128-bit target after the union allowance.
    assert!(
        certificate["trusteeEvaluationKeyProofAccounting"]["fiatShamir"]
            ["effectiveSoundnessBitsAfterUnion"]
            .as_i64()
            .expect("effective soundness bits")
            >= 128
    );
    // The Fiat-Shamir transcript accounting binds the four family accounting
    // hashes; the private VSS hash must equal the hash carried in the matching
    // proof family row, so the per-family objects stay consistent.
    let fiat_shamir_accounting = certificate["fiatShamirTranscriptAccounting"]
        .as_object()
        .expect("Fiat-Shamir transcript accounting");
    assert_eq!(
        fiat_shamir_accounting["familyAccountingHashes"]["privateVssShare"],
        proof_family_accounting[0]["claimAccounting"]["accountingHash"]
    );
    // The leakage accounting binds the same four family hashes as the
    // Fiat-Shamir accounting, never a different set.
    let succinct_leakage_accounting = certificate["succinctLeakageAccounting"]
        .as_object()
        .expect("succinct leakage accounting");
    assert_eq!(
        succinct_leakage_accounting["familyAccountingHashes"],
        fiat_shamir_accounting["familyAccountingHashes"]
    );

    let proof_theorem_accounting = certificate["proofTheoremAccounting"]
        .as_object()
        .expect("proof theorem accounting");
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
    assert_minimal_collective_setup_package_refused_without_handoff(
        "duplicate current proof accounting row",
        |package| {
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
            rebind_setup_proof_accounting_certificate_hash(package);
        },
        "setupProofAccountingCertificatePayloadMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_succinct_leakage_accounting_hash() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_succinct_leakage_accounting_hash",
    );
    assert_minimal_collective_setup_package_refused_without_handoff(
        "tampered succinct leakage family accounting hash",
        |package| {
            package["setupProofAccountingCertificate"]["succinctLeakageAccounting"]["familyAccountingHashes"]
                ["trusteeEvaluationKey"] = serde_json::json!("0".repeat(128));
            rebind_setup_proof_accounting_certificate_hash(package);
        },
        "setupProofAccountingCertificatePayloadMismatch",
    );
}

#[test]
fn collective_setup_verifier_checks_he_security_certificate() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_checks_he_security_certificate");
    assert_minimal_collective_setup_package_refused(
        "HE security certificate with an exposed extended basis class",
        |package| {
            package["heSecurityCertificate"]["assessedRing"]["largestExposedBasisClass"] =
                serde_json::json!("Q_extended");
            rebind_collective_he_security_certificate_hash(package);
        },
        "heSecurityCertificateMismatch",
    );
}

#[test]
fn he_security_certificate_records_direct_evaluator_parameter_margins() {
    let certificate = accepted_he_security_certificate_value().expect("HE security certificate");
    let assessed_ring = certificate["assessedRing"]
        .as_object()
        .expect("assessed ring object");

    assert_eq!(certificate["objectVersion"], serde_json::json!(1));
    assert_eq!(assessed_ring["largestExposedBasisClass"], "Q_data");
    assert_eq!(
        assessed_ring["largestExposedModulusBits"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(
        assessed_ring["dataPrimeCeilLog2Product"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(
        assessed_ring["extendedUtilityCeilLog2Product"],
        serde_json::json!(extended_basis_modulus_bits())
    );

    assert_eq!(certificate["estimatorBinding"]["tool"], "Lattice Estimator");
    assert_eq!(
        certificate["estimatorBinding"]["estimatorCommit"],
        "27a581bb8e9d49f5e9e2db315bd48ac769d5f5f5"
    );
    assert_eq!(
        certificate["estimatorBinding"]["largestExposedBasisClass"],
        "Q_data"
    );

    let estimator_rows = &certificate["latticeEstimatorRows"];
    let current_q_data_row = &estimator_rows["currentQDataCenteredBinomialEta2"];
    assert_eq!(
        current_q_data_row["modulusCeilLog2"],
        serde_json::json!(data_basis_modulus_bits())
    );
    assert_eq!(current_q_data_row["weakestAttack"], "bdd");
    assert!(log2_string_field(current_q_data_row, "weakestAttackCostLog2") >= 128.0);
    assert!(log2_string_field(current_q_data_row, "marginTo128Bits") > 11.0);

    let extended_boundary_row = &estimator_rows["qExtendedIfExposedCenteredBinomialEta2"];
    assert_eq!(
        extended_boundary_row["modulusCeilLog2"],
        serde_json::json!(extended_basis_modulus_bits())
    );
    assert!(log2_string_field(extended_boundary_row, "weakestAttackCostLog2") >= 128.0);
    assert!(log2_string_field(extended_boundary_row, "marginTo128Bits") > 3.0);

    // The old 868-bit shortcut is not valid for the current centered-binomial
    // error model, so the certificate must bind a failing boundary row instead
    // of treating the published Gaussian table row as direct closure evidence.
    let centered_binomial_boundary_row = &estimator_rows["boundaryTwoPower868CenteredBinomialEta2"];
    assert!(log2_string_field(centered_binomial_boundary_row, "weakestAttackCostLog2") < 128.0);

    let published_reference_row = &estimator_rows["bcc25ReferenceTwoPower868Gaussian319"];
    assert!(log2_string_field(published_reference_row, "weakestAttackCostLog2") >= 128.0);

    // The forward-looking target-decryption profile identifier stays bound; the
    // self-attested readiness/coverage flags around it were dropped.
    assert!(
        certificate["targetDecryptionStatus"]["targetDecryptionProfileId"]
            .as_str()
            .is_some_and(|profile_id| !profile_id.is_empty())
    );
}

fn log2_string_field(row: &serde_json::Value, field_name: &str) -> f64 {
    row[field_name]
        .as_str()
        .unwrap_or_else(|| panic!("{field_name} must be a decimal string"))
        .parse()
        .unwrap_or_else(|error| panic!("{field_name} must parse as f64: {error}"))
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
        certificate["collectivePublicKey"]["status"],
        "collective-public-key-coefficients-recomputed-from-public-key-share-material-and-succinct-proof-roots"
    );
    assert_eq!(
        certificate["publicEvaluationKeys"]["status"],
        "public-evaluation-key-roots-recomputed-from-frozen-schedule-and-proof-bearing-relinearization-and-galois-records"
    );
    // The certificate binds its dependency certificate hashes straight from the
    // setup package, so the verifier-recomputed body cannot drift from the
    // proof-accounting and HE-security certificates it depends on.
    assert_eq!(
        certificate["certificateDependencies"]["setupProofAccountingCertificateHash"],
        package["setupProofAccountingCertificateHash"]
    );
    assert_eq!(
        certificate["certificateDependencies"]["heSecurityCertificateHash"],
        package["heSecurityCertificateHash"]
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

    let result = verify_collective_setup_package(package);

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
    assert_eq!(certificate["livenessModel"]["model"], "secure-with-abort");
    // The adversary model still records the operative confidentiality bound:
    // the tolerated corrupt-trustee count must stay strictly below the full
    // roster participant count.
    let corrupt_trustee_bound =
        certificate["adversaryModel"]["secretConfidentialityCorruptTrusteeBound"]
            .as_u64()
            .expect("confidentiality corrupt-trustee bound");
    let participant_count = certificate["livenessModel"]["participantCount"]
        .as_u64()
        .expect("liveness participant count");
    assert!(corrupt_trustee_bound < participant_count);
    assert_eq!(
        certificate["dependencyHashes"]["setupKeyCorrectnessCertificateHash"],
        package["setupKeyCorrectnessCertificateHash"]
    );
    // The remaining-dependency list stays empty and never reintroduces a legacy
    // open-soundness dependency row.
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
}

#[test]
fn collective_setup_verifier_checks_active_static_setup_theorem_certificate() {
    assert_minimal_collective_setup_package_refused(
        "active-static setup theorem certificate with an inflated corrupt-trustee tolerance",
        |package| {
            package["activeStaticSetupTheoremCertificate"]["adversaryModel"]["secretConfidentialityCorruptTrusteeBound"] =
                serde_json::json!(9_999_u64);
        },
        "activeStaticSetupTheoremCertificatePayloadMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_active_static_setup_theorem_certificate_hash_drift() {
    assert_minimal_collective_setup_package_refused(
        "drifted active-static setup theorem certificate self-hash",
        |package| {
            package["activeStaticSetupTheoremCertificate"]["activeStaticSetupTheoremCertificateHash"] =
                serde_json::json!(valid_hash('a'));
            package["activeStaticSetupTheoremCertificateHash"] = serde_json::json!(valid_hash('a'));
        },
        "activeStaticSetupTheoremCertificateHashMismatch",
    );
}
