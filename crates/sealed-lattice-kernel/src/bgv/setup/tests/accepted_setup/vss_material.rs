use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_vss_commitment_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_commitment_records",
    );
    assert_minimal_collective_setup_package_refused(
        "VSS coefficient commitments replaced with an array",
        |package| {
            package["vssCoefficientCommitments"] = serde_json::json!([]);
        },
        "vssCoefficientCommitmentsNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "VSS coefficient commitment with a wrong RNS prime",
        |package| {
            package["vssCoefficientCommitments"]["sourceTrusteeRecords"][0]["coefficientCommitments"]
                [0]["rnsPrime"] = serde_json::json!(65_537);
            rebind_collective_vss_commitment_roots(package);
        },
        "vssCoefficientCommitmentRnsPrimeMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_threshold_commitment_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_threshold_commitment_material",
    );
    assert_minimal_collective_setup_package_refused(
        "VSS coefficient commitment material replaced with an array",
        |package| {
            package["vssCoefficientCommitmentMaterial"] = serde_json::json!([]);
        },
        "vssCoefficientCommitmentMaterialNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "tampered VSS coefficient commitment material limb row",
        |package| {
            package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"][0]["commitment"]
                ["commitmentLimbs"][0]["rows"][0][0] = serde_json::json!(42);
            rebind_collective_vss_coefficient_commitment_material_root(package);
        },
        "thresholdShareCommitmentDerivationMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_threshold_share_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_threshold_share_commitments",
    );
    assert_minimal_collective_setup_package_refused(
        "tampered threshold share commitment ring-degree status",
        |package| {
            package["thresholdShareCommitments"]["recipientRecords"][0]["limbCommitments"][0]["ringDegreeStatus"] =
                serde_json::json!("profile-ring");
            rebind_collective_threshold_share_commitment_root(package);
        },
        "thresholdShareCommitmentSetMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_transported_vss_material_when_certificate_metadata_drifted() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_transported_vss_material_when_certificate_metadata_drifted",
    );
    let mut package = minimal_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let transport_derivation =
        derive_threshold_share_commitments_from_transport_request(&serde_json::json!({
            "setupContext": package["setupContext"],
            "publicMatrixSeedHash": package["commonRandomness"]["publicMatrixSeedHash"],
            "vssCoefficientCommitmentRoot": package["vssCoefficientCommitments"]["vssCoefficientCommitmentRoot"],
            "sourceTrusteeCoefficientCommitmentRecords": package["vssCoefficientCommitments"]["sourceTrusteeRecords"],
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }))
        .expect("transported threshold derivation");
    package["vssCoefficientCommitmentMaterial"] =
        transport_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] =
        transport_derivation["thresholdShareCommitments"].clone();
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let missing_transport_result =
        verify_collective_bgv_setup_package(&package, &serde_json::json!({}))
            .expect("missing transported material result");
    assert_eq!(missing_transport_result["verifierStatus"], "pending");
    assert_eq!(
        missing_transport_result["currentPhase"],
        "thresholdShareCommitments"
    );
    assert_eq!(
        missing_transport_result["missingObjects"][0],
        "verifiedVssCoefficientCommitmentMaterial"
    );

    let transported_result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedVssCoefficientCommitmentMaterial": transported_material,
        }),
    )
    .expect("transported material result");
    assert_eq!(transported_result["verifierStatus"], "refused");
    assert_eq!(
        transported_result["currentPhase"],
        "setupPackageVerification"
    );
    // The transport certificate is assembled from synthetic chunk hashes that do
    // not match the bytes of the actually transported VSS material, so the binary
    // transport reference check refuses on the chunk-root/full-object hash. The
    // byte-length and chunk-count metadata are roster-and-ring consistent (the
    // certificate derives them from the material), so the earlier metadata check
    // passes and the hash mismatch is the operative refusal.
    assert_eq!(
        transported_result["refusedObjects"][0]["reasonCode"],
        "vssMaterialTransportReferenceHashMismatch"
    );
}

#[test]
fn collective_setup_verifier_uses_stream_verified_vss_material_without_chunk_sidecar() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_uses_stream_verified_vss_material_without_chunk_sidecar",
    );
    let mut package = minimal_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let stream_derivation = stream_verified_vss_material_from_package(
        &package,
        &transported_material,
        "accepted-setup-vss-stream-test",
    );
    package["vssCoefficientCommitmentMaterial"] =
        stream_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] = stream_derivation["thresholdShareCommitments"].clone();
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedVssCoefficientCommitmentMaterial": transported_material_reference_value(&transported_material),
            "verifiedVssCoefficientCommitmentMaterial": stream_derivation["verifiedVssCoefficientCommitmentMaterial"],
        }),
    )
    .expect("verification response");

    assert_ne!(result["currentPhase"], "thresholdShareCommitments");
    assert!(
        !result["missingObjects"]
            .as_array()
            .expect("missing objects")
            .iter()
            .any(|missing| missing == "verifiedVssCoefficientCommitmentMaterial")
    );
}

#[test]
fn collective_setup_verifier_refuses_unmatched_stream_verified_vss_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_unmatched_stream_verified_vss_material",
    );
    let mut package = minimal_collective_setup_package();
    let material_bytes = encode_transport_material_from_package(&package);
    let transported_material = transported_material_value(&material_bytes);
    let stream_derivation = stream_verified_vss_material_from_package(
        &package,
        &transported_material,
        "accepted-setup-vss-stream-unmatched-test",
    );
    package["vssCoefficientCommitmentMaterial"] =
        stream_derivation["vssCoefficientCommitmentMaterial"].clone();
    package["thresholdShareCommitments"] = stream_derivation["thresholdShareCommitments"].clone();
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let setup_transport_certificate =
        setup_transport_certificate_fixture(&profile, &package["vssCoefficientCommitmentMaterial"]);
    package["setupTransportCertificate"] = setup_transport_certificate.clone();
    package["setupTransportCertificateHash"] =
        setup_transport_certificate["setupTransportCertificateHash"].clone();
    rebind_active_static_setup_theorem_certificate(&mut package);
    rebind_collective_setup_package_hash(&mut package);
    let mut forged_verified_material =
        stream_derivation["verifiedVssCoefficientCommitmentMaterial"].clone();
    forged_verified_material["verificationId"] = serde_json::json!("missing-vss-stream");

    let result = verify_collective_bgv_setup_package(
        &package,
        &serde_json::json!({
            "transportedVssCoefficientCommitmentMaterial": transported_material_reference_value(&transported_material),
            "verifiedVssCoefficientCommitmentMaterial": forged_verified_material,
        }),
    )
    .expect("verification response");

    assert_eq!(result["verifierStatus"], "refused");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "thresholdShareCommitmentVerifiedMaterialMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_private_vss_envelope_commitments",
    );
    assert_minimal_collective_setup_package_refused(
        "private VSS envelope commitments replaced with an array",
        |package| {
            package["privateVssEnvelopeCommitments"] = serde_json::json!([]);
        },
        "privateVssEnvelopeCommitmentsNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope AAD hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["privateEnvelopeAadHash"] =
                serde_json::json!(valid_hash('4'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEnvelopeAadHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
                serde_json::json!(valid_hash('6'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope binding",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["ciphertextContentType"] = serde_json::json!("wrong-private-vss-envelope");
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeBindingMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope KEM ciphertext hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["kemCiphertextHash"] = serde_json::json!(valid_hash('9'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeKemCiphertextHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope ciphertext bytes hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["ciphertextBytesHash"] = serde_json::json!(valid_hash('8'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope recipient mailbox public-key hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["recipientMailboxPublicKeyHash"] =
                serde_json::json!(valid_hash('7'));
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEnvelopeMailboxPublicKeyMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS encrypted envelope recipient mailbox public-key bytes hash",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
                ["recipientMailboxPublicKeyBytesHash"] = serde_json::json!(valid_hash('3'));
            rebind_first_private_vss_encrypted_envelope_hash(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong private VSS envelope commitment root",
        |package| {
            package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
                serde_json::json!(valid_hash('5'));
        },
        "privateVssEnvelopeCommitmentRootMismatch",
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_share_acceptance_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_share_acceptance_records",
    );
    assert_minimal_collective_setup_package_refused(
        "VSS share acceptances replaced with an array",
        |package| {
            package["vssShareAcceptances"] = serde_json::json!([]);
        },
        "vssShareAcceptancesNotObject",
    );

    assert_minimal_collective_setup_package_refused(
        "wrong VSS share acceptance source trustee commitment root",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["sourceTrusteeCommitmentRoot"] =
                serde_json::json!(valid_hash('3'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "drifted private VSS envelope local verification root",
        |package| {
            package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('9'));
            rebind_first_private_vss_envelope_commitment_record_root(package);
            rebind_collective_private_vss_envelope_commitment_root(package);
        },
        "vssShareAcceptancePrivateEnvelopeRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "wrong VSS share acceptance local verification root",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["localVerificationRoot"] =
                serde_json::json!(valid_hash('4'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptanceLocalVerificationRootMismatch",
    );

    assert_minimal_collective_setup_package_refused_without_handoff(
        "wrong VSS share acceptance private envelope hash",
        |package| {
            package["vssShareAcceptances"]["acceptanceRecords"][0]["privateEnvelopeHash"] =
                serde_json::json!(valid_hash('8'));
            rebind_collective_vss_acceptance_root(package);
        },
        "vssShareAcceptancePrivateEnvelopeHashMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "tampered VSS share acceptance signature",
        |package| {
            let acceptance_record = &mut package["vssShareAcceptances"]["acceptanceRecords"][0];
            let signature_envelope = acceptance_record
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
            signature_envelope["signatureBytesHex"] =
                serde_json::json!(tampered_signature_bytes_hex);
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
            signature_envelope["signatureHash"] =
                serde_json::json!(signature_envelope_hash.clone());
            acceptance_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
            rebind_collective_vss_acceptance_root(package);
        },
        "InvalidSignature",
    );
}

#[test]
fn collective_setup_verifier_aborts_on_valid_vss_complaint() {
    let _accepted_setup_test_timing =
        accepted_setup_test_timing("collective_setup_verifier_aborts_on_valid_vss_complaint");
    let mut package = minimal_collective_setup_package();
    package["vssComplaints"] = vss_complaints_object(
        &package["setupContext"],
        &package["privateVssEnvelopeCommitments"],
        &package["vssCoefficientCommitments"],
        0,
        1,
    );
    rebind_collective_setup_package_hash(&mut package);

    let result = verify_collective_setup_package(&package);

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "aborted");
    assert_eq!(result["currentPhase"], "vssAcceptanceOrComplaint");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssComplaintAcceptedAbort"
    );
    assert_eq!(result["acceptedHashes"], serde_json::json!([]));
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_complaint_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_complaint_records",
    );
    assert_minimal_collective_setup_package_refused(
        "wrong VSS complaint source trustee commitment root",
        |package| {
            package["vssComplaints"] = vss_complaints_object(
                &package["setupContext"],
                &package["privateVssEnvelopeCommitments"],
                &package["vssCoefficientCommitments"],
                0,
                1,
            );
            package["vssComplaints"]["complaintRecords"][0]["sourceTrusteeCommitmentRoot"] =
                serde_json::json!(valid_hash('3'));
            rebind_collective_vss_complaint_root(package);
        },
        "vssComplaintSourceTrusteeCommitmentRootMismatch",
    );

    assert_minimal_collective_setup_package_refused(
        "tampered VSS complaint signature",
        |package| {
            package["vssComplaints"] = vss_complaints_object(
                &package["setupContext"],
                &package["privateVssEnvelopeCommitments"],
                &package["vssCoefficientCommitments"],
                0,
                1,
            );
            let complaint_record = &mut package["vssComplaints"]["complaintRecords"][0];
            let signature_envelope = complaint_record
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
            signature_envelope["signatureBytesHex"] =
                serde_json::json!(tampered_signature_bytes_hex);
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
            signature_envelope["signatureHash"] =
                serde_json::json!(signature_envelope_hash.clone());
            complaint_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
            rebind_collective_vss_complaint_root(package);
        },
        "InvalidSignature",
    );
}
