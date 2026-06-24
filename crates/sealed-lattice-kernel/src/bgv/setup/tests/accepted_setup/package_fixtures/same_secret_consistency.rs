use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn same_secret_consistency_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    vss_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let decryption_threshold = participant_count / 3 + 1;
    let mut statement_records = Vec::new();
    let mut trustee_secret_commitment_roots = Vec::new();
    let same_secret_proof_family_binding_root = derive_protocol_hash(
        "SameSecretProofFamilyBindingRoot",
        &serde_json::json!({
            "objectType": "SameSecretProofFamilyBinding",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "anchorArgument": "one keyless succinct linkage proof per trustee; secret-dependent families bind the anchor root and open the same commitment values",
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
            "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
            "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
        }),
    )
    .expect("same-secret proof family binding root");
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let source_trustee_record =
            &vss_coefficient_commitments["sourceTrusteeRecords"][trustee_roster_position as usize];
        let vss_source_trustee_commitment_root =
            source_trustee_record["sourceTrusteeCommitmentRoot"]
                .as_str()
                .expect("source trustee commitment root");
        let constant_coefficient_commitment_roots = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, rns_prime)| {
                let commitment_root = source_trustee_record["coefficientCommitments"]
                    .as_array()
                    .expect("coefficient commitments")
                    .iter()
                    .find(|coefficient_record| {
                        coefficient_record["rnsLimbIndex"].as_u64() == Some(rns_limb_index as u64)
                            && coefficient_record["shamirCoefficientIndex"].as_u64() == Some(0)
                    })
                    .and_then(|coefficient_record| coefficient_record["commitmentRoot"].as_str())
                    .expect("constant commitment root");
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "shamirCoefficientIndex": 0,
                    "commitmentRoot": commitment_root,
                })
            })
            .collect::<Vec<_>>();
        let trustee_secret_commitment_payload = serde_json::json!({
            "objectType": "TrusteeSecretCommitment",
            "objectVersion": 1,
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": vss_source_trustee_commitment_root,
            "constantCoefficientCommitmentRoots": constant_coefficient_commitment_roots,
        });
        let trustee_secret_commitment_root = derive_protocol_hash(
            "TrusteeSecretCommitmentRoot",
            &trustee_secret_commitment_payload,
        )
        .expect("trustee secret commitment root");
        let mut statement_record = serde_json::json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupProfileHash": setup_profile_hash,
            "qShareHash": q_share_hash,
            "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
            "commitmentProfileHash": commitment_profile_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": vss_source_trustee_commitment_root,
            "constantCoefficientCommitmentRoots": trustee_secret_commitment_payload["constantCoefficientCommitmentRoots"].clone(),
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
            "genericKeySwitchBindingPolicy": "absent-unless-frozen-schedule-requires-proof-family",
            "targetDecryptionBindingPolicy": "later-target-share-must-bind-threshold-share-commitment",
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        statement_record["sameSecretStatementRoot"] = serde_json::json!(
            derive_protocol_hash("SameSecretConsistencyRoot", &statement_record)
                .expect("same-secret statement root")
        );
        trustee_secret_commitment_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "trusteeSecretCommitmentRoot": trustee_secret_commitment_root,
        }));
        statement_records.push(statement_record);
    }
    let mut same_secret_consistency = serde_json::json!({
        "objectType": "SameSecretConsistencyStatementSet",
        "objectVersion": 1,
        "proofFamily": "same-secret-linkage-anchor",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": decryption_threshold,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitments["vssCoefficientCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "trusteeSecretCommitmentRoots": trustee_secret_commitment_roots,
        "statementRecords": statement_records,
    });
    same_secret_consistency["sameSecretConsistencyRoot"] = serde_json::json!(
        derive_protocol_hash("SameSecretConsistencyRoot", &same_secret_consistency)
            .expect("same-secret consistency root")
    );

    same_secret_consistency
}
