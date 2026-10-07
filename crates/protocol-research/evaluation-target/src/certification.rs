use crate::target::VerifiedEvaluationTarget;
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use registration_credentials::target_signing::{CERTIFICATION_CONTEXT, TargetVote};
use std::sync::Arc;

#[derive(Debug, PartialEq, Eq)]
pub enum Error {
    Shape,
    Context,
    Signature,
    Incomplete,
}

fn verify_vote(
    identity: &[u8; 64],
    keys: &[[u8; 1952]],
    packet: &[u8],
) -> Result<TargetVote, Error> {
    let vote = TargetVote::parse(packet).map_err(|_| Error::Shape)?;
    if vote.target() != identity {
        return Err(Error::Context);
    }
    let public = keys.get(vote.position()).ok_or(Error::Context)?;
    let public = ml_dsa_65::PublicKey::try_from_bytes(*public).map_err(|_| Error::Signature)?;
    if !public.verify(identity, vote.signature(), CERTIFICATION_CONTEXT) {
        return Err(Error::Signature);
    }
    Ok(vote)
}

/// The collector accepts only an owning evaluation capability, never a
/// claimed target body, claimed acceptance vector or supplied public-key list.
pub struct CertificateCollector {
    target: Arc<VerifiedEvaluationTarget>,
    keys: Vec<[u8; 1952]>,
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
        let count = self.keys.len();
        count - (count - 1) / 3
    }
    pub fn accepted(&self) -> usize {
        self.votes.iter().filter(|value| value.is_some()).count()
    }
    /// Invalid and duplicate packets never replace an already verified vote.
    pub fn insert(&mut self, packet: &[u8]) -> Result<bool, Error> {
        let vote = verify_vote(self.target.identity(), &self.keys, packet)?;
        let slot = &mut self.votes[vote.position()];
        if slot.is_some() {
            return Ok(false);
        }
        *slot = Some(vote);
        Ok(true)
    }
    pub fn certificate(&self) -> Result<VerifiedTargetCertificate, Error> {
        if self.accepted() < self.threshold() {
            return Err(Error::Incomplete);
        }
        Ok(VerifiedTargetCertificate {
            target: self.target.clone(),
            votes: self.votes.iter().filter_map(Clone::clone).collect(),
        })
    }
}

/// Cryptographic certificate evidence. Publication of this certificate and its
/// complete dependencies to the relay remains a lifecycle step, and no relay
/// receipt replaces any predicate verified here.
pub struct VerifiedTargetCertificate {
    target: Arc<VerifiedEvaluationTarget>,
    votes: Vec<TargetVote>,
}
impl VerifiedTargetCertificate {
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
