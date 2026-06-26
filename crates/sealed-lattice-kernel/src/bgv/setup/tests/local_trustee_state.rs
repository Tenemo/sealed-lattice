use super::*;

#[test]
fn local_trustee_setup_state_verifier_accepts_roots_only_commitment() {
    let request = local_trustee_setup_state_request();

    let result = verify_local_trustee_setup_state_from_request(&request)
        .expect("local trustee setup state verification");

    assert_eq!(result["ok"], true);
    assert_eq!(result["operation"], "verifyLocalTrusteeSetupState");
    assert_eq!(result["setupProfileId"], "CollectiveBgvSetup-v1");
    assert_eq!(result["trusteeIdentity"], "trustee-3");
    assert_eq!(result["trusteeRosterPosition"], 3);
    assert_eq!(result["trusteePoint"], 4);
    assert_eq!(
        result["targetDecryptionProofWitnessRoot"],
        request["localStateCommitment"]["targetDecryptionProofWitnessRoot"]
    );
    assert!(
        result["localStateRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn local_trustee_setup_state_verifier_rejects_deletion_receipt_trustee_drift() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]["deletionReceipt"]["trusteeIdentity"] =
        serde_json::json!("trustee-drift");
    rebind_local_deletion_receipt_root(&mut request);
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("deletion receipt trustee drift must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(error.message.contains("trustee binding"));
}

#[test]
fn local_trustee_setup_state_verifier_rejects_missing_target_proof_witness_root() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]
        .as_object_mut()
        .expect("local state")
        .remove("targetDecryptionProofWitnessRoot");
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("missing target proof witness root must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(error.message.contains("targetDecryptionProofWitnessRoot"));
}

fn local_trustee_setup_state_request() -> serde_json::Value {
    let profile = describe_collective_bgv_setup_profile().expect("profile");
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_protocol_hash(
        "ElectionManifestHash",
        &serde_json::json!({ "manifest": "local-trustee-state-test" }),
    )
    .expect("manifest hash");
    let roster_hash = derive_protocol_hash(
        "RosterHash",
        &serde_json::json!({ "roster": "local-trustee-state-test" }),
    )
    .expect("roster hash");
    let setup_profile_hash = profile["setupProfileHash"]
        .as_str()
        .expect("setup profile hash");
    let q_share_hash = profile["qShareHash"].as_str().expect("Q_share hash");
    let carry_aware_vss_relation_profile_hash = profile["carryAwareVssShareRelationProfileHash"]
        .as_str()
        .expect("carry-aware VSS relation profile hash");
    let commitment_profile_hash = profile["commitmentProfileHash"]
        .as_str()
        .expect("commitment profile hash");
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
    });
    let trustee_identity = "trustee-3";
    let trustee_roster_position = 3_u64;
    let trustee_point = trustee_roster_position + 1;
    let deletion_receipt = serde_json::json!({
        "objectType": "LocalTrusteeSetupStateDeletionReceipt",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": trustee_roster_position,
        "trusteePoint": trustee_point,
    });
    let deletion_receipt_root =
        derive_protocol_hash("LocalTrusteeDeletionReceiptRoot", &deletion_receipt)
            .expect("deletion receipt root");
    let mut local_state = serde_json::json!({
        "objectType": "LocalTrusteeSetupStateCommitment",
        "objectVersion": 1,
        "setupProfileId": "CollectiveBgvSetup-v1",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupProfileHash": setup_profile_hash,
        "qShareHash": q_share_hash,
        "carryAwareVssShareRelationProfileHash": carry_aware_vss_relation_profile_hash,
        "commitmentProfileHash": commitment_profile_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": trustee_roster_position,
        "trusteePoint": trustee_point,
        "thresholdShareCommitmentRecipientRoot": valid_hash('1'),
        "aggregateThresholdShareRoot": valid_hash('2'),
        "targetDecryptionProofWitnessRoot": valid_hash('3'),
        "issuedVssAcceptanceRoot": valid_hash('4'),
        "issuedVssComplaintRoots": [valid_hash('5')],
        "deletionReceiptRoot": deletion_receipt_root,
        "deletionReceipt": deletion_receipt,
    });
    local_state["localStateRoot"] = serde_json::json!(
        derive_protocol_hash("LocalTrusteeSetupStateRoot", &local_state).expect("local state root")
    );

    serde_json::json!({
        "setupContext": setup_context,
        "localStateCommitment": local_state,
    })
}

fn rebind_local_deletion_receipt_root(request: &mut serde_json::Value) {
    request["localStateCommitment"]["deletionReceiptRoot"] = serde_json::json!(
        derive_protocol_hash(
            "LocalTrusteeDeletionReceiptRoot",
            &request["localStateCommitment"]["deletionReceipt"],
        )
        .expect("deletion receipt root")
    );
}

fn rebind_local_state_root(request: &mut serde_json::Value) {
    request["localStateCommitment"]
        .as_object_mut()
        .expect("local state")
        .remove("localStateRoot");
    request["localStateCommitment"]["localStateRoot"] = serde_json::json!(
        derive_protocol_hash(
            "LocalTrusteeSetupStateRoot",
            &request["localStateCommitment"],
        )
        .expect("local state root")
    );
}
