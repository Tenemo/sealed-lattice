use super::*;
use crate::bgv::{
    evaluator::engine::encode_slots_to_coefficients,
    evaluator::records::target_layout_hash,
    profile::{direct_comparison_profile_hash, profile_hash},
    setup::generate_passive_setup_package_from_request,
};

mod recombination;

fn setup_request() -> Value {
    json!({
        "ceremonyId": "target-decryption-ceremony",
        "manifestHash": derive_protocol_hash(
            "ElectionManifestHash",
            &json!({ "manifest": "target-decryption-test" }),
        ).expect("manifest hash"),
        "rosterHash": derive_protocol_hash(
            "RosterHash",
            &json!({ "roster": "target-decryption-test" }),
        ).expect("roster hash"),
        "thresholdProfileHash": derive_protocol_hash(
            "ThresholdProfileHash",
            &json!({ "threshold": "target-decryption-test" }),
        ).expect("threshold hash"),
        "participants": [
            { "trusteeIdentity": "trustee-1", "rosterPosition": 0, "boardPosition": 3 },
            { "trusteeIdentity": "trustee-2", "rosterPosition": 1, "boardPosition": 1 },
            { "trusteeIdentity": "trustee-3", "rosterPosition": 2, "boardPosition": 2 }
        ],
        "setupSeed": "target-decryption-setup-seed",
    })
}

fn setup_package() -> Value {
    generate_passive_setup_package_from_request(&setup_request()).expect("setup package")
}

fn target_share_profile(setup_package: &Value) -> Value {
    let profile = json!({
        "objectType": "TargetDecryptionShareProfile",
        "objectVersion": 1,
        "thresholdProfileHash": setup_package["setupInputs"]["thresholdProfileHash"],
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileBindingHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileBindingHash"],
        "decryptionThreshold": 2,
        "minimumSharesForInterpolation": 2,
        "decryptionShareQuorum": 2,
        "selectedShareRule": SELECTED_SHARE_RULE,
    });
    let mut with_hash = profile;
    with_hash["targetShareProfileHash"] = json!(
        derive_protocol_hash("TargetDecryptionShareProfileHash", &with_hash)
            .expect("target share profile hash")
    );
    with_hash
}

fn level_zero_ciphertext(key: &DevelopmentBgvKey, slots: &[u64], seed: &str) -> Ciphertext {
    let coefficients = encode_slots_to_coefficients(slots).expect("encode slots");
    let full = key
        .encrypt_coefficients(&coefficients, seed)
        .expect("encrypt coefficients");
    Ciphertext {
        components: vec![
            vec![full.components[0][0].clone()],
            vec![full.components[1][0].clone()],
        ],
        level: 0,
        decrypt_scaling: 1,
    }
}

fn sparse_target_slots(ids: &[u64], orders: &[u64]) -> (Vec<u64>, Vec<u64>) {
    let mut target_ids = vec![0_u64; POLYNOMIAL_DEGREE];
    let mut target_orders = vec![0_u64; POLYNOMIAL_DEGREE];
    for option in 0..MAXIMUM_OPTION_COUNT {
        target_ids[packed_score_slot(option)] = ids[option];
        target_orders[packed_score_slot(option)] = orders[option];
    }
    (target_ids, target_orders)
}

fn accepted_record(
    setup_package: &Value,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
) -> Value {
    let mut record = json!({
        "objectType": "TargetAcceptedRecord",
        "objectVersion": 1,
        "ceremonyId": setup_package["setupInputs"]["ceremonyId"],
        "electionManifestHash": setup_package["setupInputs"]["manifestHash"],
        "targetFinalityScope": "target-decryption-test-finality",
        "targetProposalHash": derive_protocol_hash(
            "TargetProposalHash",
            &json!({ "target": "accepted" }),
        ).expect("proposal hash"),
        "evaluatorReplayRecordHash": derive_protocol_hash(
            "EvaluatorReplayRecordHash",
            &json!({ "replay": "accepted" }),
        ).expect("replay hash"),
        "targetContextHash": derive_protocol_hash(
            "TargetContextHash",
            &json!({ "context": "accepted target" }),
        ).expect("context hash"),
        "targetFinalityRecordHash": derive_protocol_hash(
            "TargetFinalityRecordHash",
            &json!({ "finality": "record" }),
        ).expect("record hash"),
        "targetFinalityCheckpointHash": derive_protocol_hash(
            "TargetFinalityCheckpointHash",
            &json!({ "finality": "checkpoint" }),
        ).expect("checkpoint hash"),
        "evaluatorReplayProfileHash": direct_comparison_profile_hash()
            .expect("direct comparison profile hash"),
        "targetPreimageHash": derive_protocol_hash(
            "TargetPreimageHash",
            &json!({ "preimage": "accepted" }),
        ).expect("preimage hash"),
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "targetDecryptionProfileHash": setup_package["targetDecryptionStatus"]["targetDecryptionProfileHash"],
        "targetDecryptionProfileId": TARGET_DECRYPTION_PROFILE_ID,
        "targetBasisHash": derive_protocol_hash(
            "TargetBasisHash",
            &json!({ "basis": "test" }),
        ).expect("target basis hash"),
        "acceptanceMode": "evaluator-replay",
        "boardSequence": 0,
        "boardPosition": 0,
        "organizerIdentity": "organizer",
    });
    record["targetAcceptedRecordHash"] = json!(
        derive_protocol_hash("TargetAcceptedRecordHash", &record)
            .expect("target accepted record hash")
    );
    record
}

fn target_fixture() -> (Value, Value, Value, Value) {
    let setup_package = setup_package();
    let evaluator_key = development_evaluator_key_from_passive_setup_package(
        &setup_package,
        "target-decryption-setup-seed",
    )
    .expect("evaluator key");
    let mut ids = vec![0_u64; MAXIMUM_OPTION_COUNT];
    let mut orders = vec![0_u64; MAXIMUM_OPTION_COUNT];
    ids[0] = 1;
    ids[2] = 3;
    orders[0] = 1;
    orders[2] = 2;
    let (target_id_slots, target_order_slots) = sparse_target_slots(&ids, &orders);
    let target_id = level_zero_ciphertext(&evaluator_key, &target_id_slots, "target-id");
    let target_order = level_zero_ciphertext(&evaluator_key, &target_order_slots, "target-order");
    let target_id_root =
        crate::bgv::evaluator::engine::ciphertext_object_root(&target_id).expect("target id root");
    let target_order_root = crate::bgv::evaluator::engine::ciphertext_object_root(&target_order)
        .expect("target order root");
    let aggregate_ciphertext_root = "a".repeat(128);
    let target_layout_hash = target_layout_hash(MAXIMUM_OPTION_COUNT).expect("layout hash");
    let target_ciphertext_hash = direct_target_ciphertext_hash(
        &aggregate_ciphertext_root,
        2,
        &target_layout_hash,
        &target_id_root,
        &target_order_root,
    )
    .expect("target ciphertext hash");
    let accepted_record =
        accepted_record(&setup_package, &target_ciphertext_hash, &target_layout_hash);
    let target_ciphertext_binding = json!({
        "aggregateCiphertextRoot": aggregate_ciphertext_root,
        "topCount": 2,
        "targetLayoutHash": target_layout_hash,
    });
    let target_ciphertexts = json!({
        "targetIdCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_id)
            .expect("target id hex"),
        "targetOrderCanonicalBytesHex": crate::bgv::evaluator::engine::ciphertext_canonical_bytes_hex(&target_order)
            .expect("target order hex"),
    });

    (
        setup_package,
        accepted_record,
        target_ciphertext_binding,
        target_ciphertexts,
    )
}

fn generate_share(
    setup_package: &Value,
    accepted_record: &Value,
    target_ciphertext_binding: &Value,
    target_ciphertexts: &Value,
    target_share_profile: &Value,
    trustee_identity: &str,
) -> Value {
    generate_bgv_target_decryption_share_from_request(&json!({
        "setupPackage": setup_package,
        "setupPrivateWitness": {
            "setupSeed": "target-decryption-setup-seed",
        },
        "targetAcceptedRecord": accepted_record,
        "targetCiphertextBinding": target_ciphertext_binding,
        "targetCiphertexts": target_ciphertexts,
        "targetShareProfile": target_share_profile,
        "trusteeIdentity": trustee_identity,
    }))
    .expect("generate share")
}
