use crate::{
    Credential, Refusal, SIGNATURE_BYTES, SigningPurpose,
    ballot_authentication::RetainedSetupOwner, identity::BodyHasher,
    roster_authentication::AuthenticatedRosterProposal, target_signing::TargetMessage,
};
use std::ops::RangeInclusive;
use supported_profile::relation::{release_coefficient_bytes, release_header_position};
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, RELEASE_HEADER_BYTES, SYSTEMATIC, release_relation},
};

pub const RELEASE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/release-envelope/v1";
/// The poll, setup and target identities, the author's position, the body
/// length and the body identity.
pub const RELEASE_ENVELOPE_BYTES: usize = 3 * 64 + 2 + 8 + 64;
/// The complete proof length and the release statement header.
pub const RELEASE_BODY_HEADER_BYTES: usize = 8 + RELEASE_HEADER_BYTES;

/// Bytes of a partial decryption: one release-modulus coefficient per row.
pub fn partial_bytes(profile: Profile) -> usize {
    SYSTEMATIC * release_coefficient_bytes(profile)
}
pub fn proof_lengths(profile: Profile) -> RangeInclusive<usize> {
    PROOF_HEADER_BYTES..=release_relation(profile).maximum_proof_bytes()
}
pub fn body_lengths(profile: Profile) -> RangeInclusive<usize> {
    let fixed = RELEASE_BODY_HEADER_BYTES + partial_bytes(profile);
    let proofs = proof_lengths(profile);
    fixed + proofs.start()..=fixed + proofs.end()
}

#[derive(Clone)]
pub struct ReleaseEnvelope {
    bytes: Vec<u8>,
    poll: [u8; 64],
    setup_identity: [u8; 64],
    target: [u8; 64],
    position: usize,
    length: usize,
    identity: [u8; 64],
}
impl ReleaseEnvelope {
    pub fn new(
        profile: Profile,
        poll: [u8; 64],
        setup_identity: [u8; 64],
        target: [u8; 64],
        position: usize,
        length: usize,
        identity: [u8; 64],
    ) -> Result<Self, Refusal> {
        if position >= profile.participants() || !body_lengths(profile).contains(&length) {
            return Err(Refusal::Shape);
        }
        let mut bytes = poll.to_vec();
        bytes.extend(setup_identity);
        bytes.extend(target);
        bytes.extend((position as u16).to_le_bytes());
        bytes.extend((length as u64).to_le_bytes());
        bytes.extend(identity);
        Ok(Self {
            bytes,
            poll,
            setup_identity,
            target,
            position,
            length,
            identity,
        })
    }
    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self, Refusal> {
        if bytes.len() != RELEASE_ENVELOPE_BYTES {
            return Err(Refusal::Shape);
        }
        let length = usize::try_from(u64::from_le_bytes(bytes[194..202].try_into().unwrap()))
            .map_err(|_| Refusal::Shape)?;
        Self::new(
            profile,
            bytes[..64].try_into().unwrap(),
            bytes[64..128].try_into().unwrap(),
            bytes[128..192].try_into().unwrap(),
            u16::from_le_bytes(bytes[192..194].try_into().unwrap()) as usize,
            length,
            bytes[202..].try_into().unwrap(),
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn setup_identity(&self) -> &[u8; 64] {
        &self.setup_identity
    }
    pub fn target(&self) -> &[u8; 64] {
        &self.target
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn body_length(&self) -> usize {
        self.length
    }
    pub fn body_identity(&self) -> &[u8; 64] {
        &self.identity
    }
}

/// The body header of a release statement header that names a roster
/// position of the profile.
pub fn body_header(
    profile: Profile,
    context: &[u8; RELEASE_HEADER_BYTES],
    proof_bytes: usize,
) -> Result<Vec<u8>, Refusal> {
    if release_header_position(profile, context).is_none()
        || !proof_lengths(profile).contains(&proof_bytes)
    {
        return Err(Refusal::Shape);
    }
    let mut bytes = (proof_bytes as u64).to_le_bytes().to_vec();
    bytes.extend(context);
    Ok(bytes)
}
pub fn proof_length(profile: Profile, header: &[u8]) -> Result<usize, Refusal> {
    if header.len() != RELEASE_BODY_HEADER_BYTES {
        return Err(Refusal::Shape);
    }
    let proof = usize::try_from(u64::from_le_bytes(header[..8].try_into().unwrap()))
        .map_err(|_| Refusal::Shape)?;
    if body_header(profile, header[8..].try_into().unwrap(), proof)? != header {
        return Err(Refusal::Shape);
    }
    Ok(proof)
}
/// The hasher of a release body of the length.
pub fn body_hasher(profile: Profile, length: usize) -> Result<BodyHasher, Refusal> {
    if !body_lengths(profile).contains(&length) {
        return Err(Refusal::Shape);
    }
    BodyHasher::new("sealed-lattice/release-body/v1", length)
}

impl Credential {
    pub fn begin_release(
        &mut self,
        owner: &RetainedSetupOwner,
        roster: &AuthenticatedRosterProposal,
        message: &TargetMessage,
    ) -> Result<(), Refusal> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        self.check_unlocked(SigningPurpose::Release)?;
        if !message.has_result()
            || self.release_started
            || self
                .target_lock
                .is_some_and(|target| target != *message.identity())
        {
            return Err(Refusal::Consumed);
        }
        self.target_lock = Some(*message.identity());
        self.release_started = true;
        Ok(())
    }
    pub fn sign_release(
        &mut self,
        owner: &RetainedSetupOwner,
        roster: &AuthenticatedRosterProposal,
        envelope: &ReleaseEnvelope,
    ) -> Result<[u8; SIGNATURE_BYTES], Refusal> {
        self.check_setup_owner(owner)?;
        self.check_target_predecessors(owner, roster)?;
        let record = roster
            .proposal()
            .records()
            .get(owner.position())
            .ok_or(Refusal::Context)?;
        if !self.release_started || self.release_signed {
            return Err(Refusal::Consumed);
        }
        if self.target_lock.as_ref() != Some(envelope.target())
            || envelope.poll() != owner.poll()
            || envelope.setup_identity() != owner.setup_identity()
            || envelope.position() != owner.position()
            || record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Refusal::Context);
        }
        self.release_signed = true;
        self.sign_deterministically(envelope.bytes(), RELEASE_SIGNATURE_CONTEXT)
    }
}

#[cfg(test)]
#[path = "release-signing-tests.rs"]
mod tests;
