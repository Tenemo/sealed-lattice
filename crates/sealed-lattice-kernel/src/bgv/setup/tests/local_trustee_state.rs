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
        result["exportPolicy"],
        "roots-only-no-raw-share-or-opening-export"
    );
    assert_eq!(result["deletionBoundary"], "after-private-vss-aggregation");
    assert!(
        result["localStateRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
}

#[test]
fn local_trustee_setup_state_verifier_rejects_nested_raw_share_material() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]["debugPayload"] = serde_json::json!({
        "rawShamirShares": [1, 2, 3],
    });
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("raw share material must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(error.message.contains("rawShamirShares"));
}

#[test]
fn local_trustee_setup_state_verifier_rejects_unknown_commitment_fields() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]["debugPayload"] = serde_json::json!({
        "operatorNote": "not part of the typed local state commitment",
    });
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("unknown local state fields must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("not allowed by the local trustee state schema")
    );
}

#[test]
fn local_trustee_setup_state_verifier_rejects_unknown_deletion_receipt_fields() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]["deletionReceipt"]["debugPayload"] = serde_json::json!({
        "operatorNote": "not part of the typed deletion receipt",
    });
    rebind_local_deletion_receipt_root(&mut request);
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("unknown deletion receipt fields must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(
        error
            .message
            .contains("not allowed by the local trustee state schema")
    );
}

#[test]
fn local_trustee_setup_state_verifier_rejects_deletion_receipt_drift() {
    let mut request = local_trustee_setup_state_request();
    request["localStateCommitment"]["deletionReceipt"]["deletedMaterialClasses"][0] =
        serde_json::json!("raw-share-deletion-not-recorded");
    rebind_local_deletion_receipt_root(&mut request);
    rebind_local_state_root(&mut request);

    let error = verify_local_trustee_setup_state_from_request(&request)
        .expect_err("deletion receipt drift must be refused");

    assert_eq!(
        error.code,
        crate::encoding::CanonicalErrorCode::InvalidFixture
    );
    assert!(error.message.contains("deletedMaterialClasses"));
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
    let mut deletion_receipt = serde_json::json!({
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
        "deletionBoundary": "after-private-vss-aggregation",
        "deletedMaterialClasses": [
            "raw-per-dealer-vss-shares",
            "raw-per-dealer-vss-openings",
            "private-vss-envelope-payloads-after-aggregation"
        ],
        "retainedMaterialClasses": [
            "aggregate-threshold-share-sealed",
            "issued-vss-acceptance-roots",
            "issued-vss-complaint-roots",
            "setup-context"
        ],
    });
    deletion_receipt["deletionReceiptRoot"] = serde_json::json!(
        derive_protocol_hash("LocalTrusteeDeletionReceiptRoot", &deletion_receipt)
            .expect("deletion receipt root")
    );
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
        "issuedVssAcceptanceRoot": valid_hash('4'),
        "issuedVssComplaintRoots": [valid_hash('5')],
        "deletionReceiptRoot": deletion_receipt["deletionReceiptRoot"],
        "deletionReceipt": deletion_receipt,
        "exportPolicy": "roots-only-no-raw-share-or-opening-export",
        "storageProfile": "encrypted-local-device-state-required",
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
    request["localStateCommitment"]["deletionReceipt"]
        .as_object_mut()
        .expect("deletion receipt")
        .remove("deletionReceiptRoot");
    request["localStateCommitment"]["deletionReceipt"]["deletionReceiptRoot"] = serde_json::json!(
        derive_protocol_hash(
            "LocalTrusteeDeletionReceiptRoot",
            &request["localStateCommitment"]["deletionReceipt"],
        )
        .expect("deletion receipt root")
    );
    request["localStateCommitment"]["deletionReceiptRoot"] =
        request["localStateCommitment"]["deletionReceipt"]["deletionReceiptRoot"].clone();
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
