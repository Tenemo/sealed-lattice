use super::*;

#[test]
fn collective_setup_verifier_refuses_malformed_vss_commitment_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_commitment_records",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssCoefficientCommitments"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentsNotObject"
    );

    let mut wrong_limb_package = minimal_collective_setup_package();
    wrong_limb_package["vssCoefficientCommitments"]["sourceTrusteeRecords"][0]["coefficientCommitments"]
        [0]["rnsPrime"] = serde_json::json!(65_537);
    rebind_collective_vss_commitment_roots(&mut wrong_limb_package);
    rebind_collective_setup_package_hash(&mut wrong_limb_package);

    let wrong_limb_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_limb_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_limb_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_limb_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentRnsPrimeMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_threshold_commitment_material() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_threshold_commitment_material",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssCoefficientCommitmentMaterial"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssCoefficientCommitmentMaterialNotObject"
    );

    let mut tampered_material_package = minimal_collective_setup_package();
    tampered_material_package["vssCoefficientCommitmentMaterial"]["coefficientCommitments"][0]["commitment"]
        ["commitmentLimbs"][0]["rows"][0][0] = serde_json::json!(42);
    rebind_collective_vss_coefficient_commitment_material_root(&mut tampered_material_package);
    rebind_collective_setup_package_hash(&mut tampered_material_package);

    let tampered_material_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_material_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_material_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_material_result["refusedObjects"][0]["reasonCode"],
        "thresholdShareCommitmentDerivationMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_tampered_threshold_share_commitments() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_tampered_threshold_share_commitments",
    );
    let mut tampered_threshold_package = minimal_collective_setup_package();
    tampered_threshold_package["thresholdShareCommitments"]["recipientRecords"][0]["limbCommitments"]
        [0]["ringDegreeStatus"] = serde_json::json!("profile-ring");
    rebind_collective_threshold_share_commitment_root(&mut tampered_threshold_package);
    rebind_collective_setup_package_hash(&mut tampered_threshold_package);

    let tampered_threshold_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_threshold_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_threshold_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_threshold_result["refusedObjects"][0]["reasonCode"],
        "thresholdShareCommitmentSetMismatch"
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

    let missing_transport_result = verify_collective_bgv_setup_package_from_request(
        &serde_json::json!({ "setupPackage": package.clone() }),
    )
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

    let transported_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material,
    }))
    .expect("transported material result");
    assert_eq!(transported_result["verifierStatus"], "refused");
    assert_eq!(
        transported_result["currentPhase"],
        "setupPackageVerification"
    );
    assert_eq!(
        transported_result["refusedObjects"][0]["reasonCode"],
        "vssMaterialTransportReferenceMetadataMismatch"
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

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material_reference_value(&transported_material),
        "verifiedVssCoefficientCommitmentMaterial": stream_derivation["verifiedVssCoefficientCommitmentMaterial"],
    }))
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

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
        "transportedVssCoefficientCommitmentMaterial": transported_material_reference_value(&transported_material),
        "verifiedVssCoefficientCommitmentMaterial": forged_verified_material,
    }))
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
    let mut array_package = minimal_collective_setup_package();
    array_package["privateVssEnvelopeCommitments"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeCommitmentsNotObject"
    );

    let mut wrong_aad_package = minimal_collective_setup_package();
    wrong_aad_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["privateEnvelopeAadHash"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_aad_package);
    rebind_collective_setup_package_hash(&mut wrong_aad_package);

    let wrong_aad_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_aad_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_aad_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_aad_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeAadHashMismatch"
    );

    let mut wrong_encrypted_hash_package = minimal_collective_setup_package();
    wrong_encrypted_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelopeHash"] =
        serde_json::json!(valid_hash('6'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_encrypted_hash_package);
    rebind_collective_setup_package_hash(&mut wrong_encrypted_hash_package);

    let wrong_encrypted_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_encrypted_hash_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_encrypted_hash_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_encrypted_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeHashMismatch"
    );

    let mut wrong_encrypted_binding_package = minimal_collective_setup_package();
    wrong_encrypted_binding_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["ciphertextContentType"] = serde_json::json!("wrong-private-vss-envelope");
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_encrypted_binding_package);
    rebind_collective_setup_package_hash(&mut wrong_encrypted_binding_package);

    let wrong_encrypted_binding_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_encrypted_binding_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_encrypted_binding_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_encrypted_binding_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeBindingMismatch"
    );

    let mut wrong_kem_ciphertext_hash_package = minimal_collective_setup_package();
    wrong_kem_ciphertext_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["kemCiphertextHash"] = serde_json::json!(valid_hash('9'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_kem_ciphertext_hash_package);
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_kem_ciphertext_hash_package);
    rebind_collective_setup_package_hash(&mut wrong_kem_ciphertext_hash_package);

    let wrong_kem_ciphertext_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_kem_ciphertext_hash_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_kem_ciphertext_hash_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_kem_ciphertext_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeKemCiphertextHashMismatch"
    );

    let mut wrong_ciphertext_bytes_hash_package = minimal_collective_setup_package();
    wrong_ciphertext_bytes_hash_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]
        ["encryptedEnvelope"]["ciphertextBytesHash"] = serde_json::json!(valid_hash('8'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_ciphertext_bytes_hash_package);
    rebind_collective_private_vss_envelope_commitment_root(
        &mut wrong_ciphertext_bytes_hash_package,
    );
    rebind_collective_setup_package_hash(&mut wrong_ciphertext_bytes_hash_package);

    let wrong_ciphertext_bytes_hash_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_ciphertext_bytes_hash_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_ciphertext_bytes_hash_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_ciphertext_bytes_hash_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeCiphertextBytesHashMismatch"
    );

    let mut wrong_mailbox_key_package = minimal_collective_setup_package();
    wrong_mailbox_key_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["recipientMailboxPublicKeyHash"] =
        serde_json::json!(valid_hash('7'));
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_mailbox_key_package);
    rebind_collective_setup_package_hash(&mut wrong_mailbox_key_package);

    let wrong_mailbox_key_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_mailbox_key_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_mailbox_key_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_mailbox_key_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeMailboxPublicKeyMismatch"
    );

    let mut wrong_mailbox_key_bytes_package = minimal_collective_setup_package();
    wrong_mailbox_key_bytes_package["privateVssEnvelopeCommitments"]["envelopeReferences"][0]["encryptedEnvelope"]
        ["recipientMailboxPublicKeyBytesHash"] = serde_json::json!(valid_hash('3'));
    rebind_first_private_vss_encrypted_envelope_hash(&mut wrong_mailbox_key_bytes_package);
    rebind_collective_private_vss_envelope_commitment_root(&mut wrong_mailbox_key_bytes_package);
    rebind_collective_setup_package_hash(&mut wrong_mailbox_key_bytes_package);

    let wrong_mailbox_key_bytes_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_mailbox_key_bytes_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_mailbox_key_bytes_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_mailbox_key_bytes_result["refusedObjects"][0]["reasonCode"],
        "privateVssEncryptedEnvelopeMailboxPublicKeyBytesHashMismatch"
    );

    let mut wrong_root_package = minimal_collective_setup_package();
    wrong_root_package["privateVssEnvelopeCommitments"]["privateVssEnvelopeCommitmentRoot"] =
        serde_json::json!(valid_hash('5'));
    rebind_collective_setup_package_hash(&mut wrong_root_package);

    let wrong_root_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": wrong_root_package,
    }))
    .expect("verification response");

    assert_eq!(wrong_root_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_root_result["refusedObjects"][0]["reasonCode"],
        "privateVssEnvelopeCommitmentRootMismatch"
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_share_acceptance_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_share_acceptance_records",
    );
    let mut array_package = minimal_collective_setup_package();
    array_package["vssShareAcceptances"] = serde_json::json!([]);
    rebind_collective_setup_package_hash(&mut array_package);

    let array_result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": array_package,
    }))
    .expect("verification response");

    assert_eq!(array_result["verifierStatus"], "refused");
    assert_eq!(
        array_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptancesNotObject"
    );

    let mut wrong_source_trustee_root_package = minimal_collective_setup_package();
    wrong_source_trustee_root_package["vssShareAcceptances"]["acceptanceRecords"][0]["sourceTrusteeCommitmentRoot"] =
        serde_json::json!(valid_hash('3'));
    rebind_collective_vss_acceptance_root(&mut wrong_source_trustee_root_package);
    rebind_collective_setup_package_hash(&mut wrong_source_trustee_root_package);

    let wrong_source_trustee_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_source_trustee_root_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_source_trustee_root_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_source_trustee_root_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptanceSourceTrusteeCommitmentRootMismatch"
    );

    let mut wrong_local_verification_package = minimal_collective_setup_package();
    wrong_local_verification_package["vssShareAcceptances"]["acceptanceRecords"][0]["localVerificationRoot"] =
        serde_json::json!(valid_hash('4'));
    rebind_collective_vss_acceptance_root(&mut wrong_local_verification_package);
    rebind_collective_setup_package_hash(&mut wrong_local_verification_package);

    let wrong_local_verification_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_local_verification_package,
        }))
        .expect("verification response");

    assert_eq!(wrong_local_verification_result["verifierStatus"], "refused");
    assert_eq!(
        wrong_local_verification_result["refusedObjects"][0]["reasonCode"],
        "vssShareAcceptanceLocalVerificationRootMismatch"
    );

    let mut tampered_signature_package = minimal_collective_setup_package();
    let acceptance_record =
        &mut tampered_signature_package["vssShareAcceptances"]["acceptanceRecords"][0];
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
    acceptance_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_vss_acceptance_root(&mut tampered_signature_package);
    rebind_collective_setup_package_hash(&mut tampered_signature_package);

    let tampered_signature_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_signature_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_signature_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_signature_result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
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

    let result = verify_collective_bgv_setup_package_from_request(&serde_json::json!({
        "setupPackage": package,
    }))
    .expect("verification response");

    assert_eq!(result["ok"], false);
    assert_eq!(result["verifierStatus"], "aborted");
    assert_eq!(result["currentPhase"], "vssAcceptanceOrComplaint");
    assert_eq!(
        result["refusedObjects"][0]["reasonCode"],
        "vssComplaintAcceptedAbort"
    );
    assert!(
        result["acceptedHashes"]
            .as_array()
            .expect("accepted hashes")[0]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn collective_setup_verifier_refuses_malformed_vss_complaint_records() {
    let _accepted_setup_test_timing = accepted_setup_test_timing(
        "collective_setup_verifier_refuses_malformed_vss_complaint_records",
    );
    let mut wrong_source_trustee_root_package = minimal_collective_setup_package();
    wrong_source_trustee_root_package["vssComplaints"] = vss_complaints_object(
        &wrong_source_trustee_root_package["setupContext"],
        &wrong_source_trustee_root_package["privateVssEnvelopeCommitments"],
        &wrong_source_trustee_root_package["vssCoefficientCommitments"],
        0,
        1,
    );
    wrong_source_trustee_root_package["vssComplaints"]["complaintRecords"][0]["sourceTrusteeCommitmentRoot"] =
        serde_json::json!(valid_hash('3'));
    rebind_collective_vss_complaint_root(&mut wrong_source_trustee_root_package);
    rebind_collective_setup_package_hash(&mut wrong_source_trustee_root_package);

    let wrong_source_trustee_root_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": wrong_source_trustee_root_package,
        }))
        .expect("verification response");

    assert_eq!(
        wrong_source_trustee_root_result["verifierStatus"],
        "refused"
    );
    assert_eq!(
        wrong_source_trustee_root_result["refusedObjects"][0]["reasonCode"],
        "vssComplaintSourceTrusteeCommitmentRootMismatch"
    );

    let mut tampered_signature_package = minimal_collective_setup_package();
    tampered_signature_package["vssComplaints"] = vss_complaints_object(
        &tampered_signature_package["setupContext"],
        &tampered_signature_package["privateVssEnvelopeCommitments"],
        &tampered_signature_package["vssCoefficientCommitments"],
        0,
        1,
    );
    let complaint_record = &mut tampered_signature_package["vssComplaints"]["complaintRecords"][0];
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
    complaint_record["signatureEnvelopeHash"] = serde_json::json!(signature_envelope_hash);
    rebind_collective_vss_complaint_root(&mut tampered_signature_package);
    rebind_collective_setup_package_hash(&mut tampered_signature_package);

    let tampered_signature_result =
        verify_collective_bgv_setup_package_from_request(&serde_json::json!({
            "setupPackage": tampered_signature_package,
        }))
        .expect("verification response");

    assert_eq!(tampered_signature_result["verifierStatus"], "refused");
    assert_eq!(
        tampered_signature_result["refusedObjects"][0]["reasonCode"],
        "InvalidSignature"
    );
}
