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
        let mut reveal_record = serde_json::json!({
            "objectType": "CommonRandomnessReveal",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity.clone(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHex": reveal_hex,
        });
        let reveal_hash = derive_canonical_object_hash(&reveal_record).expect("reveal hash");
        let reveal_byte_length =
            u64::try_from(canonical_json(&reveal_record).expect("reveal record").len())
                .expect("reveal record length");
        let reveal_context_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "CommonRandomnessRevealSignatureContext",
            "purpose": "common-randomness-reveal-signature-context",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "rosterPosition": roster_position,
            "objectRoot": reveal_hash.as_str(),
        }))
        .expect("reveal signature context hash");
        let signature_seed_label = setup_trustee_signature_seed_label(&trustee_identity);
        let reveal_signature_fixture = create_protocol_signature_fixture(
            &signature_seed_label,
            serde_json::json!({
                "objectType": "CommonRandomnessReveal",
                "objectVersion": 1,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "boardHeadHash": null,
                "objectRoot": reveal_hash.as_str(),
                "chunkMerkleRoot": null,
                "byteLength": reveal_byte_length,
                "signerRole": "Trustee",
                "signerIdentity": trustee_identity.as_str(),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "contextHash": reveal_context_hash,
            }),
        )
        .expect("reveal signature fixture");
        reveal_record["revealHash"] = serde_json::json!(reveal_hash.clone());
        reveal_record["signatureEnvelopeHash"] =
            reveal_signature_fixture.envelope["signatureHash"].clone();
        reveal_record["signatureEnvelope"] = reveal_signature_fixture.envelope;
        ordered_reveal_hashes.push(reveal_hash.clone());
        reveal_records.push(reveal_record);

        let mut commit_record = serde_json::json!({
            "objectType": "CommonRandomnessCommit",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity.as_str(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHash": reveal_hash.as_str(),
        });
        let commit_hash = derive_canonical_object_hash(&commit_record).expect("commit hash");
        let commit_byte_length =
            u64::try_from(canonical_json(&commit_record).expect("commit record").len())
                .expect("commit record length");
        let commit_context_hash = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "CommonRandomnessCommitSignatureContext",
            "purpose": "common-randomness-commit-signature-context",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "rosterPosition": roster_position,
            "objectRoot": commit_hash.as_str(),
        }))
        .expect("commit signature context hash");
        let commit_signature_fixture = create_protocol_signature_fixture(
            &signature_seed_label,
            serde_json::json!({
                "objectType": "CommonRandomnessCommit",
                "objectVersion": 1,
                "ceremonyId": ceremony_id,
                "manifestHash": manifest_hash,
                "boardHeadHash": null,
                "objectRoot": commit_hash.as_str(),
                "chunkMerkleRoot": null,
                "byteLength": commit_byte_length,
                "signerRole": "Trustee",
                "signerIdentity": trustee_identity.as_str(),
                "recoveryEpoch": 0,
                "deviceEpoch": 0,
                "contextHash": commit_context_hash,
            }),
        )
        .expect("commit signature fixture");
        commit_record["commitHash"] = serde_json::json!(commit_hash);
        commit_record["signatureEnvelopeHash"] =
            commit_signature_fixture.envelope["signatureHash"].clone();
        commit_record["signatureEnvelope"] = commit_signature_fixture.envelope;
        commit_records.push(commit_record);
    }

    let public_matrix_seed_hash = derive_canonical_object_hash(&serde_json::json!({
    "objectType": "SetupPublicMatrixSeed",
    "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "orderedRevealHashes": ordered_reveal_hashes,
    }))
    .expect("public matrix seed hash");
    // The public matrices are derived per roster decryption threshold, so the
    // fixture must derive them with the same threshold the verifier recomputes
    // for this roster, not the first-closure default the standalone command uses.
    let public_derivations = crate::bgv::setup::accepted_setup::derive_collective_bgv_setup_public_derivations_for_roster(
        &public_matrix_seed_hash,
        participant_count / 3 + 1,
    )
    .expect("public derivations");
    assert_eq!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["matrixKind"],
        "commitment"
    );
    assert!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["sampledEntries"]
            .as_array()
            .expect("commitment matrix sampled entries")
            .len()
            > 1
    );
    assert!(
        public_derivations["publicMatrices"]["commitmentMatrix"]["sampledEntries"][0]
            ["coefficientValue"]
            .as_u64()
            .is_some()
    );
    let mut common_randomness = serde_json::json!({
        "objectType": "SetupCommonRandomness",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "commitRecords": commit_records,
        "revealRecords": reveal_records,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicDerivations": public_derivations,
    });
    let common_randomness_root =
        derive_canonical_object_hash(&common_randomness).expect("common randomness root");
    common_randomness["commonRandomnessRoot"] = serde_json::json!(common_randomness_root);

    common_randomness
}
