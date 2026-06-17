use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn private_vss_envelope_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let vss_coefficient_commitment_root =
        vss_coefficient_commitments["vssCoefficientCommitmentRoot"]
            .as_str()
            .expect("VSS coefficient commitment root");
    let phase_order_hash = derive_protocol_hash(
        "CollectiveBgvSetupPhaseOrderHash",
        &serde_json::json!([
            {"phaseId": "rosterFreeze", "phaseNumber": 1},
            {"phaseId": "setupIntent", "phaseNumber": 2},
            {"phaseId": "commonRandomnessCommit", "phaseNumber": 3},
            {"phaseId": "commonRandomnessReveal", "phaseNumber": 4},
            {"phaseId": "vssCoefficientCommitments", "phaseNumber": 5},
            {"phaseId": "privateVssEnvelopeDelivery", "phaseNumber": 6},
            {"phaseId": "recipientVssVerification", "phaseNumber": 7},
            {"phaseId": "vssAcceptanceOrComplaint", "phaseNumber": 8},
            {"phaseId": "publicKeyShareProofs", "phaseNumber": 9},
            {"phaseId": "relinearizationRoundOne", "phaseNumber": 10},
            {"phaseId": "relinearizationRoundTwo", "phaseNumber": 11},
            {"phaseId": "galoisKeyShareBatches", "phaseNumber": 12},
            {"phaseId": "trusteeEvaluationKeyProofs", "phaseNumber": 13},
            {"phaseId": "setupPackageAssembly", "phaseNumber": 14},
            {"phaseId": "setupPackageVerification", "phaseNumber": 15},
        ]),
    )
    .expect("phase order hash");
    let envelope_references = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
                [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root")
                .to_string();
            let phase_order_hash = phase_order_hash.clone();
            (0..participant_count).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let envelope_sequence_number = source_trustee_roster_position * participant_count + recipient_roster_position;
                let private_envelope_hash = derive_protocol_hash(
                    "PrivateVssShareEnvelopeHash",
                    &serde_json::json!({
                        "fixture": "private-vss-share-envelope",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientRosterPosition": recipient_roster_position,
                    }),
                )
                .expect("private envelope hash");
                let local_verification_root = derive_protocol_hash(
                    "PrivateVssLocalVerificationRoot",
                    &serde_json::json!({
                        "fixture": "recipient-vss-local-verification",
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientRosterPosition": recipient_roster_position,
                        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                        "privateEnvelopeHash": private_envelope_hash.as_str(),
                    }),
                )
                .expect("local verification root");
                let private_envelope_aad = serde_json::json!({
                    "objectType": "PrivateVssEnvelopeAad",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "privateEnvelopeObjectType": "PrivateVssShareEnvelope",
                    "ciphertextContentType": "private-vss-share-envelope",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "phaseOrderHash": phase_order_hash.as_str(),
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                });
                let private_envelope_aad_hash = derive_protocol_hash(
                    "PrivateVssEnvelopeAadHash",
                    &private_envelope_aad,
                )
                .expect("private envelope AAD hash");
                let recipient_mailbox_public_key_hash =
                    private_vss_mailbox_public_key_hash(recipient_roster_position);
                let recipient_mailbox_public_key_bytes_hash =
                    private_vss_mailbox_public_key_bytes_hash(recipient_roster_position);
                let kem_ciphertext_bytes = vec![0xa5_u8; 1088];
                let kem_ciphertext_hash = hash512_hex(
                    "sealed-lattice-private-vss-mailbox/ml-kem-768-ciphertext-v1",
                    &[&kem_ciphertext_bytes],
                );
                let ciphertext_bytes = vec![0xc3_u8; 96];
                let ciphertext_bytes_hash = hash512_hex(
                    "sealed-lattice-private-vss-mailbox/aes-256-gcm-ciphertext-v1",
                    &[&ciphertext_bytes],
                );
                let mut encrypted_envelope = serde_json::json!({
                    "objectType": "EncryptedPrivateVssShareEnvelope",
                    "objectVersion": 1,
                    "setupProfileId": "CollectiveBgvSetup-v1",
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "ciphertextContentType": "private-vss-share-envelope",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                    "privateEnvelopeHash": private_envelope_hash.as_str(),
                    "privateEnvelopeAad": private_envelope_aad.clone(),
                    "privateEnvelopeAadHash": private_envelope_aad_hash.as_str(),
                    "recipientMailboxPublicKeyHash": recipient_mailbox_public_key_hash.as_str(),
                    "recipientMailboxPublicKeyBytesHash": recipient_mailbox_public_key_bytes_hash.as_str(),
                    "kemCiphertextBytesHex": "a5".repeat(1088),
                    "kemCiphertextHash": kem_ciphertext_hash.as_str(),
                    "aeadNonceHex": "5a".repeat(12),
                    "ciphertextBytesHex": "c3".repeat(96),
                    "ciphertextBytesHash": ciphertext_bytes_hash.as_str(),
                    "ciphertextByteLength": 96,
                    "plaintextByteLength": 512,
                    "aeadTagLength": 128,
                });
                encrypted_envelope["encryptedEnvelopeHash"] = serde_json::json!(
                    derive_protocol_hash("PrivateVssEncryptedEnvelopeHash", &encrypted_envelope)
                        .expect("encrypted envelope hash")
                );
                let encrypted_envelope_hash = encrypted_envelope["encryptedEnvelopeHash"].clone();
                let mut envelope_reference = serde_json::json!({
                    "objectType": "PrivateVssEnvelopeCommitment",
                    "objectVersion": 1,
                    "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "envelopeSequenceNumber": envelope_sequence_number,
                    "deliveryPhaseNumber": 6,
                    "verificationPhaseNumber": 7,
                    "privateEnvelopeHash": private_envelope_hash,
                    "encryptedEnvelopeHash": encrypted_envelope_hash,
                    "privateEnvelopeAad": private_envelope_aad,
                    "privateEnvelopeAadHash": private_envelope_aad_hash,
                    "encryptedEnvelope": encrypted_envelope,
                    "recipientMailboxPublicKeyHash": recipient_mailbox_public_key_hash,
                    "localVerificationRoot": local_verification_root,
                });
                envelope_reference["privateEnvelopeCommitmentRoot"] = serde_json::json!(
                    derive_protocol_hash(
                        "PrivateVssEnvelopeCommitmentRoot",
                        &private_vss_envelope_commitment_record_root_input(&envelope_reference)
                    )
                    .expect("private envelope commitment record root")
                );

                envelope_reference
            })
        })
        .collect::<Vec<_>>();
    let mut commitment_set = serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "objectVersion": 1,
        "mailboxEncryptionProfileId": "sealed-lattice-private-vss-mailbox-ml-kem-768-hkdf-sha384-aes-256-gcm-v1",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "participantCount": participant_count,
        "envelopeCount": participant_count * participant_count,
        "deliveryPhaseNumber": 6,
        "verificationPhaseNumber": 7,
        "envelopeReferences": envelope_references,
    });
    commitment_set["privateVssEnvelopeCommitmentRoot"] = serde_json::json!(
        derive_protocol_hash(
            "PrivateVssEnvelopeCommitmentRoot",
            &private_vss_envelope_commitment_set_root_input(&commitment_set)
        )
        .expect("private VSS envelope commitment root")
    );

    commitment_set
}

#[allow(clippy::too_many_arguments)]
pub(super) fn vss_share_acceptances_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    private_vss_envelope_commitments: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root");
    let envelope_references = private_vss_envelope_commitments["envelopeReferences"]
        .as_array()
        .expect("private VSS envelope references");
    let acceptance_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
                [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root")
                .to_string();
            (0..participant_count).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let signature_seed_label = format!("{recipient_identity}-accepts-{source_trustee_identity}");
                let signing_public_key_hash =
                    create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
                        .expect("signature key fixture");
                let envelope_sequence_number =
                    (source_trustee_roster_position * participant_count + recipient_roster_position) as usize;
                let envelope_reference = &envelope_references[envelope_sequence_number];
                let private_envelope_hash = envelope_reference["privateEnvelopeHash"]
                    .as_str()
                    .expect("private envelope hash");
                let local_verification_root = envelope_reference["localVerificationRoot"]
                    .as_str()
                    .expect("local verification root");
                let acceptance_payload = serde_json::json!({
                    "objectType": "VssShareAcceptance",
                    "objectVersion": 1,
                    "ceremonyId": ceremony_id,
                    "manifestHash": manifest_hash,
                    "rosterHash": roster_hash,
                    "setupProfileHash": setup_profile_hash,
                    "qShareHash": q_share_hash,
                    "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                    "commitmentProfileHash": commitment_profile_hash,
                    "setupEpoch": setup_epoch,
                    "sourceTrusteeIdentity": source_trustee_identity,
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity,
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
                    "privateEnvelopeHash": private_envelope_hash,
                    "localVerificationRoot": local_verification_root,
                    "recoveryEpoch": 0,
                    "deviceEpoch": 0,
                    "signingPublicKeyHash": signing_public_key_hash,
                });
                let acceptance_root =
                    derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_payload)
                        .expect("acceptance root");
                let acceptance_byte_length =
                    u64::try_from(canonical_json(&acceptance_payload).expect("acceptance payload").len())
                        .expect("acceptance payload length");
                let acceptance_context_hash = derive_protocol_hash(
                    "VssShareAcceptanceRoot",
                    &serde_json::json!({
                        "purpose": "vss-share-acceptance-signature-context",
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "rosterHash": roster_hash,
                        "setupProfileHash": setup_profile_hash,
                        "qShareHash": q_share_hash,
                        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
                        "commitmentProfileHash": commitment_profile_hash,
                        "setupEpoch": setup_epoch,
                        "sourceTrusteeIdentity": source_trustee_identity,
                        "sourceTrusteeRosterPosition": source_trustee_roster_position,
                        "recipientIdentity": recipient_identity,
                        "recipientRosterPosition": recipient_roster_position,
                        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
                        "privateEnvelopeHash": private_envelope_hash,
                        "localVerificationRoot": local_verification_root,
                        "acceptanceRoot": acceptance_root,
                    }),
                )
                .expect("acceptance context hash");
                let signature_fixture = create_protocol_signature_fixture(
                    &signature_seed_label,
                    serde_json::json!({
                        "objectType": "VssShareAcceptance",
                        "objectVersion": 1,
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "boardHeadHash": null,
                        "objectRoot": acceptance_root,
                        "chunkMerkleRoot": null,
                        "byteLength": acceptance_byte_length,
                        "signerRole": "Trustee",
                        "signerIdentity": recipient_identity,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "contextHash": acceptance_context_hash,
                    }),
                )
                .expect("acceptance signature fixture");
                let signature_envelope = signature_fixture.envelope;
                let signature_envelope_hash = signature_envelope["signatureHash"].clone();
                let mut acceptance_record = acceptance_payload;
                acceptance_record["acceptanceRoot"] = serde_json::json!(acceptance_root);
                acceptance_record["acceptanceByteLength"] =
                    serde_json::json!(acceptance_byte_length);
                acceptance_record["acceptanceContextHash"] =
                    serde_json::json!(acceptance_context_hash);
                acceptance_record["signatureEnvelopeHash"] = signature_envelope_hash;
                acceptance_record["signatureEnvelope"] = signature_envelope;

                acceptance_record
            })
        })
        .collect::<Vec<_>>();
    let mut acceptance_set = serde_json::json!({
        "objectType": "VssShareAcceptanceSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "acceptanceRecords": acceptance_records,
    });
    acceptance_set["vssShareAcceptanceRoot"] = serde_json::json!(
        derive_protocol_hash("VssShareAcceptanceRoot", &acceptance_set)
            .expect("VSS share acceptance set root")
    );

    acceptance_set
}

pub(in super::super) fn vss_complaints_object(
    setup_context: &serde_json::Value,
    private_vss_envelope_commitments: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
    source_trustee_roster_position: u64,
    recipient_roster_position: u64,
) -> serde_json::Value {
    let private_vss_envelope_commitment_root =
        private_vss_envelope_commitments["privateVssEnvelopeCommitmentRoot"]
            .as_str()
            .expect("private VSS envelope commitment root");
    let ceremony_id = setup_context["ceremonyId"].as_str().expect("ceremony id");
    let manifest_hash = setup_context["manifestHash"]
        .as_str()
        .expect("manifest hash");
    let roster_hash = setup_context["rosterHash"].as_str().expect("roster hash");
    let setup_profile_hash = setup_context["setupProfileHash"]
        .as_str()
        .expect("setup profile hash");
    let q_share_hash = setup_context["qShareHash"].as_str().expect("Q_share hash");
    let carry_aware_vss_relation_profile_hash =
        setup_context["carryAwareVssShareRelationProfileHash"]
            .as_str()
            .expect("carry-aware VSS relation profile hash");
    let commitment_profile_hash = setup_context["commitmentProfileHash"]
        .as_str()
        .expect("commitment profile hash");
    let setup_epoch = setup_context["setupEpoch"].as_str().expect("setup epoch");
    let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
    let recipient_identity = format!("trustee-{recipient_roster_position}");
    let source_trustee_commitment_root = vss_coefficient_commitments["sourceTrusteeRecords"]
        [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
        .as_str()
        .expect("source trustee commitment root");
    let envelope_sequence_number =
        (source_trustee_roster_position * 10 + recipient_roster_position) as usize;
    let private_envelope_hash = private_vss_envelope_commitments["envelopeReferences"]
        [envelope_sequence_number]["privateEnvelopeHash"]
        .as_str()
        .expect("private envelope hash");
    let complaint_reason_code = "privateVssEnvelopeInvalidOpening";
    let complaint_evidence_root = derive_protocol_hash(
        "PrivateVssLocalVerificationRoot",
        &serde_json::json!({
            "fixture": "recipient-vss-complaint-evidence",
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientRosterPosition": recipient_roster_position,
            "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
            "privateEnvelopeHash": private_envelope_hash,
            "complaintReasonCode": complaint_reason_code,
        }),
    )
    .expect("complaint evidence root");
    let signature_seed_label =
        format!("{recipient_identity}-complains-about-{source_trustee_identity}");
    let signing_public_key_hash = create_ml_dsa_public_key_hash_fixture(&signature_seed_label)
        .expect("signature key fixture");
    let complaint_payload = serde_json::json!({
        "objectType": "VssShareComplaint",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "sourceTrusteeIdentity": source_trustee_identity.as_str(),
        "sourceTrusteeRosterPosition": source_trustee_roster_position,
        "recipientIdentity": recipient_identity.as_str(),
        "recipientRosterPosition": recipient_roster_position,
        "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "privateEnvelopeHash": private_envelope_hash,
        "complaintEvidenceRoot": complaint_evidence_root.as_str(),
        "complaintReasonCode": complaint_reason_code,
        "recoveryEpoch": 0,
        "deviceEpoch": 0,
        "signingPublicKeyHash": signing_public_key_hash,
    });
    let complaint_root =
        derive_protocol_hash("VssComplaintRoot", &complaint_payload).expect("complaint root");
    let complaint_byte_length = u64::try_from(
        canonical_json(&complaint_payload)
            .expect("complaint payload")
            .len(),
    )
    .expect("complaint payload length");
    let complaint_context_hash = derive_protocol_hash(
        "VssComplaintRoot",
        &serde_json::json!({
            "purpose": "vss-share-complaint-signature-context",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "sourceTrusteeIdentity": source_trustee_identity.as_str(),
            "sourceTrusteeRosterPosition": source_trustee_roster_position,
            "recipientIdentity": recipient_identity.as_str(),
            "recipientRosterPosition": recipient_roster_position,
            "sourceTrusteeCommitmentRoot": source_trustee_commitment_root,
            "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
            "privateEnvelopeHash": private_envelope_hash,
            "complaintEvidenceRoot": complaint_evidence_root.as_str(),
            "complaintReasonCode": complaint_reason_code,
            "complaintRoot": complaint_root.as_str(),
        }),
    )
    .expect("complaint context hash");
    let signature_fixture = create_protocol_signature_fixture(
        &signature_seed_label,
        serde_json::json!({
            "objectType": "VssShareComplaint",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "boardHeadHash": null,
            "objectRoot": complaint_root.as_str(),
            "chunkMerkleRoot": null,
            "byteLength": complaint_byte_length,
            "signerRole": "Trustee",
            "signerIdentity": recipient_identity.as_str(),
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "contextHash": complaint_context_hash,
        }),
    )
    .expect("complaint signature fixture");
    let signature_envelope = signature_fixture.envelope;
    let signature_envelope_hash = signature_envelope["signatureHash"].clone();
    let mut complaint_record = complaint_payload;
    complaint_record["complaintRoot"] = serde_json::json!(complaint_root);
    complaint_record["complaintByteLength"] = serde_json::json!(complaint_byte_length);
    complaint_record["complaintContextHash"] = serde_json::json!(complaint_context_hash);
    complaint_record["signatureEnvelopeHash"] = signature_envelope_hash;
    complaint_record["signatureEnvelope"] = signature_envelope;

    let mut complaint_set = serde_json::json!({
        "objectType": "VssComplaintSet",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root,
        "complaintRecords": [complaint_record],
    });
    complaint_set["vssComplaintRoot"] = serde_json::json!(
        derive_protocol_hash("VssComplaintRoot", &complaint_set).expect("VSS complaint set root")
    );

    complaint_set
}
