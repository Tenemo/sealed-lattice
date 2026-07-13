use super::*;

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn private_vss_envelope_commitments_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    vss_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&serde_json::json!({
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": participant_count,
        }))
        .expect("setup context hash");
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let vss_coefficient_commitment_root =
        vss_coefficient_commitments["vssCoefficientCommitmentRoot"]
            .as_str()
            .expect("VSS coefficient commitment root");
    let envelope_references = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            let setup_context_hash = setup_context_hash.clone();
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root =
                vss_coefficient_commitments["sourceTrusteeRecords"]
                    [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                    .as_str()
                    .expect("source trustee commitment root")
                    .to_string();
            (0..participant_count).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let private_envelope_hash = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "PrivateVssShareEnvelopeHash",
                    "fixture": "private-vss-share-envelope",
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientRosterPosition": recipient_roster_position,
                }))
                .expect("private envelope hash");
                let local_verification_root = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "PrivateVssLocalVerificationRoot",
                    "fixture": "recipient-vss-local-verification",
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "privateEnvelopeHash": private_envelope_hash.as_str(),
                }))
                .expect("local verification root");
                let private_envelope_aad = serde_json::json!({
                    "objectType": "PrivateVssEnvelopeAad",
                    "setupContextHash": setup_context_hash,
                    "publicMatrixSeedHash": public_matrix_seed_hash,
                    "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                });
                let recipient_mailbox_public_key_hash =
                    private_vss_mailbox_public_key_hash(recipient_roster_position);
                let encrypted_envelope = serde_json::json!({
                    "objectType": "EncryptedPrivateVssShareEnvelope",
                    "privateEnvelopeAad": private_envelope_aad.clone(),
                    "recipientMailboxPublicKeyHash": recipient_mailbox_public_key_hash.as_str(),
                    "kemCiphertextBytesHex": "a5".repeat(1088),
                    "aeadNonceHex": "5a".repeat(12),
                    "ciphertextBytesHex": "c3".repeat(96),
                });
                let encrypted_envelope_hash = derive_canonical_object_hash(&encrypted_envelope)
                    .expect("encrypted envelope hash");
                serde_json::json!({
                    "objectType": "PrivateVssEnvelopeCommitment",
                    "sourceTrusteeIdentity": source_trustee_identity.as_str(),
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity.as_str(),
                    "recipientRosterPosition": recipient_roster_position,
                    "privateEnvelopeHash": private_envelope_hash,
                    "encryptedEnvelopeHash": encrypted_envelope_hash,
                    "encryptedEnvelope": encrypted_envelope,
                    "localVerificationRoot": local_verification_root,
                })
            })
        })
        .collect::<Vec<_>>();
    let mut commitment_set = serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "envelopeReferences": envelope_references,
    });
    let commitment_set_root_input = serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "setupContextHash": setup_context_hash,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
        "envelopeReferences": commitment_set["envelopeReferences"].clone(),
    });
    commitment_set["privateVssEnvelopeCommitmentRoot"] = serde_json::json!(
        derive_canonical_object_hash(&private_vss_envelope_commitment_set_root_input(
            &commitment_set_root_input
        ))
        .expect("private VSS envelope commitment root")
    );

    commitment_set
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn vss_share_acceptances_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
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
    let setup_context_hash =
        crate::bgv::setup::accepted_setup::setup_context_hash(&serde_json::json!({
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "participantCount": participant_count,
        }))
        .expect("setup context hash");
    let acceptance_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            let setup_context_hash = setup_context_hash.clone();
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root =
                vss_coefficient_commitments["sourceTrusteeRecords"]
                    [source_trustee_roster_position as usize]["sourceTrusteeCommitmentRoot"]
                    .as_str()
                    .expect("source trustee commitment root")
                    .to_string();
            (0..participant_count).map(move |recipient_roster_position| {
                let recipient_identity = format!("trustee-{recipient_roster_position}");
                let signature_seed_label = setup_trustee_signature_seed_label(&recipient_identity);
                let envelope_sequence_number = (source_trustee_roster_position * participant_count
                    + recipient_roster_position)
                    as usize;
                let envelope_reference = &envelope_references[envelope_sequence_number];
                let private_envelope_hash = envelope_reference["privateEnvelopeHash"]
                    .as_str()
                    .expect("private envelope hash");
                let local_verification_root = envelope_reference["localVerificationRoot"]
                    .as_str()
                    .expect("local verification root");
                let acceptance_payload = serde_json::json!({
                    "objectType": "VssShareAcceptance",
                    "setupContextHash": setup_context_hash,
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
                });
                let acceptance_root =
                    derive_canonical_object_hash(&acceptance_payload).expect("acceptance root");
                let acceptance_context_hash = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "VssShareAcceptanceSignatureContext",
                    "payloadRoot": acceptance_root,
                }))
                .expect("acceptance context hash");
                let signature_fixture = create_protocol_signature_fixture(
                    &signature_seed_label,
                    serde_json::json!({
                        "objectType": "VssShareAcceptance",
                        "ceremonyId": ceremony_id,
                        "manifestHash": manifest_hash,
                        "objectRoot": acceptance_root,
                        "signerRole": "Trustee",
                        "signerIdentity": recipient_identity,
                        "recoveryEpoch": 0,
                        "deviceEpoch": 0,
                        "contextHash": acceptance_context_hash,
                    }),
                )
                .expect("acceptance signature fixture");
                serde_json::json!({
                    "objectType": "VssShareAcceptance",
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientRosterPosition": recipient_roster_position,
                    "signatureEnvelope": signature_fixture.envelope,
                })
            })
        })
        .collect::<Vec<_>>();
    let acceptance_set = serde_json::json!({
        "objectType": "VssShareAcceptanceSet",
        "acceptanceRecords": acceptance_records,
    });

    acceptance_set
}
