use super::*;

use crate::hashing::derive_canonical_object_hash;

fn validate_hash(value: &str) -> CanonicalResult<()> {
    if value.len() == 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Ok(());
    }
    Err(CanonicalError::new(
        CanonicalErrorCode::InvalidFixture,
        "targetFinalityPolicyHash must be a 64-byte lowercase hexadecimal hash",
    ))
}

pub(super) fn direct_ballot_target_proposal(
    evaluator_replay_record_hash: &str,
    target_finality_policy_hash: Option<&str>,
) -> CanonicalResult<Value> {
    let Some(target_finality_policy_hash) = target_finality_policy_hash else {
        return Ok(json!({}));
    };

    validate_hash(target_finality_policy_hash)?;
    let proposal_without_hash = json!({
        "objectType": "DirectEncryptedBallotTargetProposal",
        "evaluatorReplayRecordHash": evaluator_replay_record_hash,
        "targetFinalityPolicyHash": target_finality_policy_hash,
    });
    let target_proposal_hash = derive_canonical_object_hash(&proposal_without_hash)?;

    Ok(json!({
        "targetProposalHash": target_proposal_hash,
        "evaluatorReplayRecordHash": proposal_without_hash["evaluatorReplayRecordHash"],
        "targetFinalityPolicyHash": proposal_without_hash["targetFinalityPolicyHash"],
    }))
}
