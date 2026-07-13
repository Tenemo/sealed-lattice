use super::*;

use crate::hashing::derive_canonical_object_hash;

#[test]
fn local_trustee_setup_state_verifier_accepts_bound_commitment() {
    let request = local_trustee_setup_state_request();

    let result = verify_local_trustee_setup_state_from_request(&request)
        .expect("local trustee setup state verification");

    assert_eq!(result["trusteeIdentity"], "trustee-3");
    assert_eq!(result["trusteeRosterPosition"], 3);
    assert!(
        result["localStateRoot"]
            .as_str()
            .is_some_and(|hash| hash.len() == 128)
    );
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
    let mut local_state = serde_json::json!({
        "objectType": "LocalTrusteeSetupStateCommitment",
        "ceremonyId": ceremony_id,
        "manifestHash": manifest_hash,
        "rosterHash": roster_hash,
        "setupParametersHash": setup_parameters_hash,
        "setupEpoch": setup_epoch,
        "trusteeIdentity": trustee_identity,
        "trusteeRosterPosition": trustee_roster_position,
        "thresholdShareCommitmentRecipientRoot": valid_hash('1'),
        "aggregateThresholdShareRoot": valid_hash('2'),
    });
    local_state["localStateRoot"] =
        serde_json::json!(derive_canonical_object_hash(&local_state).expect("local state root"));

    serde_json::json!({
        "setupContext": setup_context,
        "localStateCommitment": local_state,
    })
}
