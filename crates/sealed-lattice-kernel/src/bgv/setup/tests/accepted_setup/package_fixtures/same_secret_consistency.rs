use super::*;

use crate::hashing::derive_canonical_object_hash;

#[allow(clippy::too_many_arguments)]
pub(super) fn same_secret_consistency_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_parameters_hash: &str,
    setup_epoch: &str,
    vss_coefficient_commitments: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let decryption_threshold = participant_count / 3 + 1;
    let mut statement_records = Vec::new();
    let same_secret_proof_family_binding_root = derive_canonical_object_hash(&serde_json::json!({
            "objectType": "SameSecretProofFamilyBinding",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
            "boundSecretDependentProofFamilies": [
                "vss-constant-relation",
                "public-key-share",
                "relinearization-key-share",
                "galois-key-share",
            ],
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
            "setupParametersHash": setup_parameters_hash,
            "setupEpoch": setup_epoch,
            "trusteeIdentity": trustee_identity.as_str(),
            "trusteeRosterPosition": trustee_roster_position,
            "vssSourceTrusteeCommitmentRoot": vss_source_trustee_commitment_root,
            "constantCoefficientCommitmentRoots": constant_coefficient_commitment_roots,
        });
        let trustee_secret_commitment_root =
            derive_canonical_object_hash(&trustee_secret_commitment_payload)
                .expect("trustee secret commitment root");
        let mut statement_record = serde_json::json!({
            "objectType": "SameSecretConsistencyStatement",
            "objectVersion": 1,
            "proofFamily": "same-secret-linkage-anchor",
            "ceremonyId": ceremony_id,
            "manifestHash": manifest_hash,
            "rosterHash": roster_hash,
            "setupParametersHash": setup_parameters_hash,
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
            "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
            "sameSecretRelation": "vss-constant-commitments-open-to-one-short-secret-across-q-share-limbs",
        });
        statement_record["sameSecretStatementRoot"] = serde_json::json!(
            derive_canonical_object_hash(&statement_record).expect("same-secret statement root")
        );
        statement_records.push(statement_record);
    }
    let mut same_secret_consistency = serde_json::json!({
        "objectType": "SameSecretConsistencyStatementSet",
        "objectVersion": 1,
        "proofFamily": "same-secret-linkage-anchor",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "participantCount": participant_count,
        "rnsLimbCount": DATA_PRIMES.len(),
        "thresholdDegree": decryption_threshold,
        "vssCoefficientCommitmentRoot": vss_coefficient_commitments["vssCoefficientCommitmentRoot"],
        "sameSecretProofFamilyBindingRoot": same_secret_proof_family_binding_root,
        "statementRecords": statement_records,
    });
    same_secret_consistency["sameSecretConsistencyRoot"] = serde_json::json!(
        derive_canonical_object_hash(&same_secret_consistency)
            .expect("same-secret consistency root")
    );

    same_secret_consistency
}
