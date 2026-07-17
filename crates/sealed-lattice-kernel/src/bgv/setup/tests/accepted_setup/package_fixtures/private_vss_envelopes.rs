use super::*;

pub(in super::super) fn private_vss_envelope_commitments_object(
    participant_count: u64,
) -> serde_json::Value {
    let envelope_references = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            (0..participant_count).map(move |recipient_roster_position| {
                let private_envelope_hash = derive_canonical_object_hash(&serde_json::json!({
                    "objectType": "PrivateVssShareEnvelopeHash",
                    "fixture": "private-vss-share-envelope",
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientRosterPosition": recipient_roster_position,
                }))
                .expect("private envelope hash");
                let encrypted_envelope = serde_json::json!({
                    "objectType": "EncryptedPrivateVssShareEnvelope",
                    "kemCiphertextBytesHex": "a5".repeat(1088),
                    "aeadNonceHex": "5a".repeat(12),
                    "ciphertextBytesHex": "c3".repeat(96),
                });
                let encrypted_envelope_hash = derive_canonical_object_hash(&encrypted_envelope)
                    .expect("encrypted envelope hash");
                serde_json::json!({
                    "objectType": "PrivateVssEnvelopeCommitment",
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientRosterPosition": recipient_roster_position,
                    "privateEnvelopeHash": private_envelope_hash,
                    "encryptedEnvelopeHash": encrypted_envelope_hash,
                    "encryptedEnvelope": encrypted_envelope,
                })
            })
        })
        .collect::<Vec<_>>();
    serde_json::json!({
        "objectType": "PrivateVssEnvelopeCommitmentSet",
        "envelopeReferences": envelope_references,
    })
}

#[allow(clippy::too_many_arguments)]
pub(in super::super) fn vss_share_acceptances_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    private_vss_envelope_commitments: &serde_json::Value,
    vss_public_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
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
    let public_matrix_seed_hash = vss_public_coefficient_commitments["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let trustee_identities = (0..participant_count)
        .map(|roster_position| format!("trustee-{roster_position}"))
        .collect::<Vec<_>>();
    let vss_coefficient_commitment_root =
        crate::bgv::setup::vss_commitment::vss_public_coefficient_commitment_set_root(
            vss_public_coefficient_commitments,
            &trustee_identities,
        )
        .expect("VSS coefficient commitment root");
    let private_vss_envelope_commitment_root = derive_canonical_object_hash(
        &private_vss_envelope_commitment_set_root_input(&serde_json::json!({
            "objectType": "PrivateVssEnvelopeCommitmentSet",
            "setupContextHash": setup_context_hash,
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "vssCoefficientCommitmentRoot": vss_coefficient_commitment_root,
            "envelopeReferences": envelope_references,
        })),
    )
    .expect("private VSS envelope commitment root");
    let acceptance_records = (0..participant_count)
        .flat_map(|source_trustee_roster_position| {
            let setup_context_hash = setup_context_hash.clone();
            let source_trustee_identity = format!("trustee-{source_trustee_roster_position}");
            let source_trustee_commitment_root =
                crate::bgv::setup::vss_commitment::vss_public_source_coefficient_record_root(
                &vss_public_coefficient_commitments["sourceTrusteeRecords"]
                    [source_trustee_roster_position as usize],
                &source_trustee_identity,
            )
            .expect("source trustee commitment root");
            let private_vss_envelope_commitment_root =
                private_vss_envelope_commitment_root.clone();
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
                let acceptance_payload = serde_json::json!({
                    "objectType": "VssShareAcceptance",
                    "setupContextHash": setup_context_hash,
                    "sourceTrusteeIdentity": source_trustee_identity,
                    "sourceTrusteeRosterPosition": source_trustee_roster_position,
                    "recipientIdentity": recipient_identity,
                    "recipientRosterPosition": recipient_roster_position,
                    "sourceTrusteeCommitmentRoot": source_trustee_commitment_root.as_str(),
                    "privateVssEnvelopeCommitmentRoot": private_vss_envelope_commitment_root.as_str(),
                    "privateEnvelopeHash": private_envelope_hash,
                });
                let acceptance_root =
                    derive_canonical_object_hash(&acceptance_payload).expect("acceptance root");
                let signature_fixture = create_protocol_signature_fixture(
                    &signature_seed_label,
                    serde_json::json!({
                        "objectType": "VssShareAcceptance",
                        "objectRoot": acceptance_root,
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
