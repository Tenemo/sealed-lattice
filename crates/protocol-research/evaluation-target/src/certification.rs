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
            .inventory()
            .setup()
            .inventory()
            .proposal()
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

/// Cryptographic certificate evidence. Durable publication of this certificate
/// and its complete dependencies remains the existing archive/lifecycle step.
/// An archive acknowledgement never replaces any predicate verified here.
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
mod tests {
    use super::*;
    use fips204::traits::{KeyGen, Signer};
    #[test]
    fn exact_target_owner_and_signature_context_are_required() {
        let (public, key) = ml_dsa_65::KG::keygen_from_seed(&[19; 32]);
        let keys = [public.into_bytes()];
        let target = [23; 64];
        let signature = key
            .try_sign_with_seed(&[31; 32], &target, CERTIFICATION_CONTEXT)
            .unwrap();
        let mut packet = Vec::from(0u16.to_le_bytes());
        packet.extend(target);
        packet.extend(signature);
        assert_eq!(
            verify_vote(&target, &keys, &packet).unwrap().encode(),
            packet
        );
        assert!(matches!(
            verify_vote(&[24; 64], &keys, &packet),
            Err(Error::Context)
        ));
        let mut changed = packet.clone();
        changed[0] = 1;
        assert!(matches!(
            verify_vote(&target, &keys, &changed),
            Err(Error::Context)
        ));
        let mut changed = packet.clone();
        changed[100] ^= 1;
        assert!(matches!(
            verify_vote(&target, &keys, &changed),
            Err(Error::Signature)
        ));
        let signature = key
            .try_sign_with_seed(&[31; 32], &target, b"sealed-lattice/close-response/v1")
            .unwrap();
        let mut changed = packet;
        changed[66..].copy_from_slice(&signature);
        assert!(matches!(
            verify_vote(&target, &keys, &changed),
            Err(Error::Signature)
        ));
    }
}
