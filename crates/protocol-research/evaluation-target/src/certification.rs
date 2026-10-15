use crate::target::VerifiedEvaluationTarget;
use protocol_foundations::SIGNING_PUBLIC_KEY_BYTES;
use protocol_foundations::target_signing::{CERTIFICATION_CONTEXT, TargetVote};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum Refusal {
    Shape,
    Context,
    Signature,
    Incomplete,
}

fn authenticate_vote(
    identity: &[u8; 64],
    keys: &[[u8; SIGNING_PUBLIC_KEY_BYTES]],
    packet: &[u8],
) -> Result<TargetVote, Refusal> {
    let vote = TargetVote::parse(packet).map_err(|_| Refusal::Shape)?;
    if vote.target() != identity {
        return Err(Refusal::Context);
    }
    let public = keys.get(vote.position()).ok_or(Refusal::Context)?;
    if !protocol_foundations::verify_purpose_signature(
        public,
        identity,
        vote.signature(),
        CERTIFICATION_CONTEXT,
    ) {
        return Err(Refusal::Signature);
    }
    Ok(vote)
}

/// The collector accepts only an owning evaluation capability, never a
/// claimed target body, claimed acceptance vector or supplied public-key list.
pub struct CertificateCollector {
    target: Arc<VerifiedEvaluationTarget>,
    keys: Vec<[u8; SIGNING_PUBLIC_KEY_BYTES]>,
    votes: Vec<Option<TargetVote>>,
}
impl CertificateCollector {
    pub fn new(target: Arc<VerifiedEvaluationTarget>) -> Self {
        let keys: Vec<_> = target
            .setup()
            .roster()
            .proposal()
            .records()
            .iter()
            .map(|record| record.header().signing_public)
            .collect();
        let votes = vec![None; keys.len()];
        Self {
            target,
            keys,
            votes,
        }
    }
    pub fn threshold(&self) -> usize {
        supported_profile::inventory_threshold(self.keys.len())
    }
    pub fn accepted(&self) -> usize {
        self.votes.iter().filter(|value| value.is_some()).count()
    }
    /// Invalid and duplicate packets never replace an already verified vote.
    pub fn insert(&mut self, packet: &[u8]) -> Result<bool, Refusal> {
        let vote = authenticate_vote(self.target.identity(), &self.keys, packet)?;
        let slot = &mut self.votes[vote.position()];
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some(vote);
        Ok(true)
    }
    pub fn certificate(&self) -> Result<VerifiedInventoryCertificate, Refusal> {
        if self.accepted() < self.threshold() {
            return Err(Refusal::Incomplete);
        }
        Ok(VerifiedInventoryCertificate {
            target: self.target.clone(),
            votes: self.votes.iter().filter_map(Clone::clone).collect(),
        })
    }
}

/// Cryptographic certificate evidence. Publication of this certificate and its
/// complete dependencies to the relay remains a lifecycle step, and no relay
/// receipt replaces any predicate verified here.
pub struct VerifiedInventoryCertificate {
    target: Arc<VerifiedEvaluationTarget>,
    votes: Vec<TargetVote>,
}
impl VerifiedInventoryCertificate {
    pub fn target(&self) -> &Arc<VerifiedEvaluationTarget> {
        &self.target
    }
    pub fn votes(&self) -> &[TargetVote] {
        &self.votes
    }
}

#[cfg(test)]
#[path = "certification-tests.rs"]
mod tests;
