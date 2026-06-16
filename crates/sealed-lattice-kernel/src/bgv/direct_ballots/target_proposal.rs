use super::*;

pub(super) fn direct_ballot_target_proposal(
    setup_package: &Value,
    aggregate_ciphertext_root: &str,
    evaluator_replay_context_hash: &str,
    evaluator_replay_record_hash: &str,
    target_ciphertext_hash: &str,
    target_layout_hash: &str,
    target_finality_policy_hash: Option<&str>,
) -> CanonicalResult<Value> {
    let Some(target_finality_policy_hash) = target_finality_policy_hash else {
        return Ok(json!({}));
    };

    validate_direct_ballot_hash_hex(target_finality_policy_hash, "targetFinalityPolicyHash")?;
    let proposal_without_hash = json!({
        "ceremonyId": required_string_path(setup_package, &["setupInputs", "ceremonyId"])?,
        "electionManifestHash": required_string_path(setup_package, &["setupInputs", "manifestHash"])?,
        "thresholdProfileHash": required_string_path(setup_package, &["setupInputs", "thresholdProfileHash"])?,
        "evaluatorReplayContextHash": evaluator_replay_context_hash,
        "evaluatorReplayRecordHash": evaluator_replay_record_hash,
        "encryptedBallotAggregateHash": aggregate_ciphertext_root,
        "targetCiphertextHash": target_ciphertext_hash,
        "targetLayoutHash": target_layout_hash,
        "evaluatorReplayProfileHash": direct_comparison_profile_hash()?,
        "targetFinalityPolicyHash": target_finality_policy_hash,
    });
    let target_proposal_hash = derive_protocol_hash("TargetProposalHash", &proposal_without_hash)?;

    Ok(json!({
        "targetProposalHash": target_proposal_hash,
        "ceremonyId": proposal_without_hash["ceremonyId"],
        "electionManifestHash": proposal_without_hash["electionManifestHash"],
        "thresholdProfileHash": proposal_without_hash["thresholdProfileHash"],
        "evaluatorReplayContextHash": proposal_without_hash["evaluatorReplayContextHash"],
        "evaluatorReplayRecordHash": proposal_without_hash["evaluatorReplayRecordHash"],
        "encryptedBallotAggregateHash": proposal_without_hash["encryptedBallotAggregateHash"],
        "targetCiphertextHash": proposal_without_hash["targetCiphertextHash"],
        "targetLayoutHash": proposal_without_hash["targetLayoutHash"],
        "evaluatorReplayProfileHash": proposal_without_hash["evaluatorReplayProfileHash"],
        "targetFinalityPolicyHash": proposal_without_hash["targetFinalityPolicyHash"],
    }))
}
