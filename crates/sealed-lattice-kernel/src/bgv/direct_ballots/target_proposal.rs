use super::*;

pub(super) struct DirectBallotTargetProposalInput<'a> {
    pub(super) setup_package: &'a Value,
    pub(super) aggregate_ciphertext_root: &'a str,
    pub(super) evaluator_replay_context_hash: &'a str,
    pub(super) evaluator_replay_record_hash: &'a str,
    pub(super) target_ciphertext_hash: &'a str,
    pub(super) target_layout_hash: &'a str,
    pub(super) target_basis_hash: &'a str,
    pub(super) target_finality_policy_hash: Option<&'a str>,
}

pub(super) fn direct_ballot_target_proposal(
    input: DirectBallotTargetProposalInput<'_>,
) -> CanonicalResult<Value> {
    let Some(target_finality_policy_hash) = input.target_finality_policy_hash else {
        return Ok(json!({}));
    };

    validate_direct_ballot_hash_hex(target_finality_policy_hash, "targetFinalityPolicyHash")?;
    let proposal_without_hash = json!({
        "ceremonyId": required_string_path(input.setup_package, &["setupInputs", "ceremonyId"])?,
        "electionManifestHash": required_string_path(input.setup_package, &["setupInputs", "manifestHash"])?,
        "thresholdProfileHash": required_string_path(input.setup_package, &["setupInputs", "thresholdProfileHash"])?,
        "evaluatorReplayContextHash": input.evaluator_replay_context_hash,
        "evaluatorReplayRecordHash": input.evaluator_replay_record_hash,
        "encryptedBallotAggregateHash": input.aggregate_ciphertext_root,
        "targetCiphertextHash": input.target_ciphertext_hash,
        "targetLayoutHash": input.target_layout_hash,
        "targetBasisHash": input.target_basis_hash,
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
        "targetBasisHash": proposal_without_hash["targetBasisHash"],
        "evaluatorReplayProfileHash": proposal_without_hash["evaluatorReplayProfileHash"],
        "targetFinalityPolicyHash": proposal_without_hash["targetFinalityPolicyHash"],
    }))
}
