use super::*;

use crate::hashing::derive_canonical_object_hash;

#[test]
fn local_trustee_setup_state_verifier_accepts_roots_only_commitment() {
    let request = local_trustee_setup_state_request();

    let result = verify_local_trustee_setup_state_from_request(&request)
        .expect("local trustee setup state verification");

    assert_eq!(result["operation"], "verifyLocalTrusteeSetupState");
    assert_eq!(result["trusteeIdentity"], "trustee-3");
    assert_eq!(result["trusteeRosterPosition"], 3);
    assert_eq!(result["trusteePoint"], 4);
    assert_eq!(result["deletionBoundary"], "after-private-vss-aggregation");
    assert!(
        result["localStateRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
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
    let ceremony_id = "ceremony-main";
    let manifest_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "ElectionManifestHash",
        "manifest": "local-trustee-state-test",
    }))
    .expect("manifest hash");
    let roster_hash = derive_canonical_object_hash(&serde_json::json!({
        "objectType": "RosterHash",
        "roster": "local-trustee-state-test",
    }))
    .expect("roster hash");
    let setup_parameters_hash =
        crate::bgv::setup::accepted_setup::setup_parameters_hash_for_roster(
            &crate::bgv::setup::accepted_setup::roster_parameters_from_participant_count(10),
        )
        .expect("roster-derived setup parameters hash");
    let setup_parameters_hash = setup_parameters_hash.as_str();
    let setup_epoch = "setup-epoch-1";
    let setup_context = serde_json::json!({
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
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
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": trustee_roster_position,
        "trusteePoint": trustee_point,
        "deletionBoundary": "after-private-vss-aggregation",
        "deletedMaterialClasses": [
            "raw-per-source-trustee-vss-shares",
            "raw-per-source-trustee-vss-openings",
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
        derive_canonical_object_hash(&deletion_receipt).expect("deletion receipt root")
    );
    let mut local_state = serde_json::json!({
        "objectType": "LocalTrusteeSetupStateCommitment",
        "objectVersion": 1,
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
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
    });
    local_state["localStateRoot"] =
        serde_json::json!(derive_canonical_object_hash(&local_state).expect("local state root"));

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
        derive_canonical_object_hash(&request["localStateCommitment"]["deletionReceipt"])
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
        derive_canonical_object_hash(&request["localStateCommitment"]).expect("local state root")
    );
}
