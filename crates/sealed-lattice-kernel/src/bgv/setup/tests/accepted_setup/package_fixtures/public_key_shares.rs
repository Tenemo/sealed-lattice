use super::*;

#[allow(clippy::too_many_arguments)]
pub(super) fn public_key_shares_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        common_randomness["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        common_randomness["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = same_secret_consistency["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let mut share_records = Vec::new();
    let mut public_key_share_roots = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let same_secret_statement = &statement_records[trustee_roster_position as usize];
        let share_coefficient_hashes = DATA_PRIMES
            .iter()
            .enumerate()
            .map(|(rns_limb_index, rns_prime)| {
                serde_json::json!({
                    "rnsLimbIndex": rns_limb_index,
                    "rnsPrime": rns_prime,
                    "component": "b_i",
                    "coefficientVectorHash512": derive_protocol_hash(
                        "PublicKeyShareRoot",
                        &serde_json::json!({
                            "fixture": "public-key-share-coefficient-vector",
                            "trusteeRosterPosition": trustee_roster_position,
                            "rnsLimbIndex": rns_limb_index,
                        }),
                    )
                    .expect("public-key share coefficient hash"),
                })
            })
            .collect::<Vec<_>>();
        let mut share_record = serde_json::json!({
            "objectType": "PublicKeyShare",
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
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "shareComponent": "component-zero-b_i",
            "rnsLimbCount": DATA_PRIMES.len(),
            "shareCoefficientVectorHash512ByLimb": share_coefficient_hashes,
            "proofBindingStatus": "public-key-share-proof-required",
        });
        share_record["publicKeyShareRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareRoot", &share_record)
                .expect("public-key share root")
        );
        public_key_share_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
        }));
        share_records.push(share_record);
    }
    let mut share_set = serde_json::json!({
        "objectType": "PublicKeyShareSet",
        "objectVersion": 1,
        "proofBindingStatus": "public-key-share-proof-required",
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
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareRoots": public_key_share_roots,
        "shareRecords": share_records,
    });
    share_set["publicKeyShareSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareRoot", &share_set).expect("public-key share set root")
    );

    share_set
}

#[allow(clippy::too_many_arguments)]
pub(super) fn public_key_share_proofs_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
    public_key_shares: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let public_matrix_seed_hash = common_randomness["publicMatrixSeedHash"]
        .as_str()
        .expect("public matrix seed hash");
    let public_key_crp_root =
        common_randomness["publicDerivations"]["crpRoots"]["publicKeyCrpRoot"]
            .as_str()
            .expect("public-key CRP root");
    let public_a_polynomial_root =
        common_randomness["publicDerivations"]["bgvPublicA"]["publicPolynomialRoot"]
            .as_str()
            .expect("public a root");
    let statement_records = same_secret_consistency["statementRecords"]
        .as_array()
        .expect("same-secret statement records");
    let share_records = public_key_shares["shareRecords"]
        .as_array()
        .expect("public-key share records");
    let mut proof_records = Vec::new();
    let mut public_key_share_proof_roots = Vec::new();
    for trustee_roster_position in 0..participant_count {
        let trustee_identity = format!("trustee-{trustee_roster_position}");
        let same_secret_statement = &statement_records[trustee_roster_position as usize];
        let share_record = &share_records[trustee_roster_position as usize];
        let mut proof_record = serde_json::json!({
            "objectType": "PublicKeyShareProof",
            "objectVersion": 1,
            "proofFamily": "public-key-share",
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
            "publicMatrixSeedHash": public_matrix_seed_hash,
            "publicKeyCrpRoot": public_key_crp_root,
            "publicAPolynomialRoot": public_a_polynomial_root,
            "publicKeyShareRoot": share_record["publicKeyShareRoot"],
            "sameSecretStatementRoot": same_secret_statement["sameSecretStatementRoot"],
            "trusteeSecretCommitmentRoot": same_secret_statement["trusteeSecretCommitmentRoot"],
            "rnsLimbCount": DATA_PRIMES.len(),
            "errorSupport": "checked-by-public-key-share-succinct-proof-set",
            "proofBytesStatus": "supplied-by-public-key-share-succinct-proof-set",
        });
        proof_record["publicKeyShareProofRoot"] = serde_json::json!(
            derive_protocol_hash("PublicKeyShareProofRoot", &proof_record)
                .expect("public-key share proof root")
        );
        public_key_share_proof_roots.push(serde_json::json!({
            "trusteeIdentity": trustee_identity,
            "trusteeRosterPosition": trustee_roster_position,
            "publicKeyShareProofRoot": proof_record["publicKeyShareProofRoot"],
        }));
        proof_records.push(proof_record);
    }
    let mut proof_set = serde_json::json!({
        "objectType": "PublicKeyShareProofSet",
        "objectVersion": 1,
        "proofFamily": "public-key-share",
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
        "publicMatrixSeedHash": public_matrix_seed_hash,
        "publicKeyCrpRoot": public_key_crp_root,
        "publicAPolynomialRoot": public_a_polynomial_root,
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareSetRoot": public_key_shares["publicKeyShareSetRoot"],
        "publicKeyShareProofRoots": public_key_share_proof_roots,
        "proofRecords": proof_records,
    });
    proof_set["publicKeyShareProofSetRoot"] = serde_json::json!(
        derive_protocol_hash("PublicKeyShareProofRoot", &proof_set)
            .expect("public-key share proof set root")
    );

    proof_set
}

#[allow(clippy::too_many_arguments)]
pub(super) fn evaluator_key_schedule_object(
    ceremony_id: &str,
    manifest_hash: &str,
    roster_hash: &str,
    setup_profile_hash: &str,
    q_share_hash: &str,
    carry_aware_vss_relation_profile_hash: &str,
    commitment_profile_hash: &str,
    setup_epoch: &str,
    profile: &serde_json::Value,
    common_randomness: &serde_json::Value,
    same_secret_consistency: &serde_json::Value,
    public_key_shares: &serde_json::Value,
    public_key_share_proofs: &serde_json::Value,
    participant_count: u64,
) -> serde_json::Value {
    let public_derivations = &common_randomness["publicDerivations"];
    let crp_roots = &public_derivations["crpRoots"];
    let schedule_profile = &profile["evaluatorKeyScheduleProfile"];
    let mut schedule = serde_json::json!({
        "objectType": "EvaluatorKeySchedule",
        "objectVersion": 1,
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
        "publicMatrixSeedHash": common_randomness["publicMatrixSeedHash"],
        "relinearizationCrpRoot": crp_roots["relinearizationCrpRoot"],
        "galoisKeyCrpRoot": crp_roots["galoisKeyCrpRoot"],
        "sameSecretConsistencyRoot": same_secret_consistency["sameSecretConsistencyRoot"],
        "publicKeyShareSetRoot": public_key_shares["publicKeyShareSetRoot"],
        "publicKeyShareProofSetRoot": public_key_share_proofs["publicKeyShareProofSetRoot"],
        "relinearizationLevelSchedule": schedule_profile["relinearizationLevelSchedule"],
        "requiredGaloisKeySchedule": schedule_profile["requiredGaloisKeySchedule"],
        "requiredGaloisSetHash": schedule_profile["requiredGaloisSetHash"],
        "genericKeySwitchPolicy": "refused-unless-explicitly-required",
    });
    schedule["evaluatorKeyScheduleRoot"] = serde_json::json!(
        derive_protocol_hash("EvaluatorKeyScheduleRoot", &schedule)
            .expect("evaluator-key schedule root")
    );

    schedule
}
