use super::*;

use crate::hashing::derive_canonical_object_hash;

#[allow(clippy::too_many_arguments)]
pub(super) fn common_randomness_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
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
    let mut commit_records = Vec::new();
    let mut reveal_records = Vec::new();
    let mut ordered_reveal_hashes = Vec::new();
    for roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{roster_position}");
        let reveal_source_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "CommonRandomnessRevealHash",
            "fixture": "common-randomness-reveal",
            "rosterPosition": roster_position,
        }))
        .expect("reveal source hash");
        let reveal_hex = reveal_source_hash[..64].to_string();
        let reveal_payload = serde_json::json!({
            "objectType": "CommonRandomnessReveal",
            "setupContextHash": &setup_context_hash,
            "trusteeIdentity": trustee_identity.clone(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHex": reveal_hex,
        });
        let reveal_hash = derive_canonical_object_hash(&reveal_payload).expect("reveal hash");
        let reveal_context_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "CommonRandomnessRevealSignatureContext",
            "payloadRoot": reveal_hash.as_str(),
        }))
        .expect("reveal signature context hash");
        let signature_seed_label = setup_trustee_signature_seed_label(&trustee_identity);
        let reveal_signature_fixture = create_protocol_signature_fixture(
            &signature_seed_label,
            serde_json::json!({
                "objectType": "CommonRandomnessReveal",
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "objectRoot": reveal_hash.as_str(),
                "signerRole": "Trustee",
                "signerIdentity": trustee_identity.as_str(),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "contextHash": reveal_context_hash,
            }),
        )
        .expect("reveal signature fixture");
        ordered_reveal_hashes.push(reveal_hash.clone());
        reveal_records.push(serde_json::json!({
            "objectType": "CommonRandomnessReveal",
            "rosterPosition": roster_position,
            "revealHex": reveal_hex,
            "signatureEnvelope": reveal_signature_fixture.envelope,
        }));

        let commit_payload = serde_json::json!({
            "objectType": "CommonRandomnessCommit",
            "setupContextHash": &setup_context_hash,
            "trusteeIdentity": trustee_identity.as_str(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHash": reveal_hash.as_str(),
        });
        let commit_hash = derive_canonical_object_hash(&commit_payload).expect("commit hash");
        let commit_context_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "CommonRandomnessCommitSignatureContext",
            "payloadRoot": commit_hash.as_str(),
        }))
        .expect("commit signature context hash");
        let commit_signature_fixture = create_protocol_signature_fixture(
            &signature_seed_label,
            serde_json::json!({
                "objectType": "CommonRandomnessCommit",
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "objectRoot": commit_hash.as_str(),
                "signerRole": "Trustee",
                "signerIdentity": trustee_identity.as_str(),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "contextHash": commit_context_hash,
            }),
        )
        .expect("commit signature fixture");
        commit_records.push(serde_json::json!({
            "objectType": "CommonRandomnessCommit",
            "rosterPosition": roster_position,
            "revealHash": reveal_hash,
            "signatureEnvelope": commit_signature_fixture.envelope,
        }));
    }

    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "SetupPublicMatrixSeed",
        "setupContextHash": setup_context_hash,
        "orderedRevealHashes": ordered_reveal_hashes,
    }))
    .expect("public matrix seed hash");
    serde_json::json!({
        "objectType": "SetupCommonRandomness",
        "commitRecords": commit_records,
        "revealRecords": reveal_records,
        "publicMatrixSeedHash": public_matrix_seed_hash,
    })
}
