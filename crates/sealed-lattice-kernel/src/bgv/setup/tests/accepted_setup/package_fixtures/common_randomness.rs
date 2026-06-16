use super::*;

pub(super) fn common_randomness_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    setup_epoch: &str,
) -> serde_json::Value {
    let mut commit_records = Vec::new();
    let mut reveal_records = Vec::new();
    let mut ordered_reveal_hashes = Vec::new();
    for roster_position in 0..10 {
        let trustee_identity = format!("trustee-{roster_position}");
        let reveal_source_hash = derive_protocol_hash(
            "CommonRandomnessRevealHash",
            &serde_json::json!({
                "fixture": "common-randomness-reveal",
                "rosterPosition": roster_position,
            }),
        )
        .expect("reveal source hash");
        let reveal_hex = reveal_source_hash[..64].to_string();
        let signature_envelope_hash = derive_protocol_hash(
            "ProtocolSignatureEnvelopeHash",
            &serde_json::json!({
                "fixture": "common-randomness-signature",
                "rosterPosition": roster_position,
            }),
        )
        .expect("signature envelope hash");
        let mut reveal_record = serde_json::json!({
            "objectType": "CommonRandomnessReveal",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity.clone(),
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHex": reveal_hex,
            "signatureEnvelopeHash": signature_envelope_hash.clone(),
        });
        let reveal_hash = derive_protocol_hash("CommonRandomnessRevealHash", &reveal_record)
            .expect("reveal hash");
        reveal_record["revealHash"] = serde_json::json!(reveal_hash.clone());
        ordered_reveal_hashes.push(reveal_hash.clone());
        reveal_records.push(reveal_record);

        let mut commit_record = serde_json::json!({
            "objectType": "CommonRandomnessCommit",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "signerRole": "Trustee",
            "trusteeIdentity": trustee_identity,
            "rosterPosition": roster_position,
            "recoveryEpoch": 0,
            "deviceEpoch": 0,
            "revealHash": reveal_hash,
            "signatureEnvelopeHash": signature_envelope_hash,
        });
        let commit_hash = derive_protocol_hash("CommonRandomnessCommitHash", &commit_record)
            .expect("commit hash");
        commit_record["commitHash"] = serde_json::json!(commit_hash);
        commit_records.push(commit_record);
    }

    let public_matrix_seed_hash = derive_protocol_hash(
        "SetupPublicMatrixSeedHash",
        &serde_json::json!({
            "setupProfileId": "CollectiveBgvSetup-v1",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "setupEpoch": setup_epoch,
            "orderedRevealHashes": ordered_reveal_hashes,
        }),
    )
    .expect("public matrix seed hash");
    let public_derivations =
        derive_collective_bgv_setup_public_derivations_from_request(&serde_json::json!({
            "publicMatrixSeedHash": public_matrix_seed_hash,
        }))
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
        "setupProfileHash": setup_profile_hash,
        "setupEpoch": setup_epoch,
        "commitRecords": commit_records,
        "revealRecords": reveal_records,
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicDerivations": public_derivations,
    });
    let common_randomness_root =
        derive_protocol_hash("SetupCommonRandomnessRoot", &common_randomness)
            .expect("common randomness root");
    common_randomness["commonRandomnessRoot"] = serde_json::json!(common_randomness_root);

    common_randomness
}
