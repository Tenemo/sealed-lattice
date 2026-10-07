use crate::{
    Credential, Error, SIGNATURE_BYTES, SigningPurpose, ballot_authentication::RetainedBallotOwner,
    identity::BodyHasher, roster_authentication::OrganizerSignedRoster,
    target_signing::TargetMessage,
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use linked_release_proof::statement::{header_position, release_coefficient_bytes};
use std::ops::RangeInclusive;
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, RELEASE_HEADER_BYTES, SYSTEMATIC, release_relation},
};

pub const RELEASE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/release-envelope/v1";
pub const RELEASE_ENVELOPE_BYTES: usize = 4 + 3 * 64 + 2 + 8 + 64;
pub const RELEASE_BODY_HEADER_BYTES: usize = 12 + RELEASE_HEADER_BYTES;

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
    inventory: [u8; 64],
    target: [u8; 64],
    position: usize,
    length: usize,
    identity: [u8; 64],
}
impl ReleaseEnvelope {
    pub fn new(
        profile: Profile,
        poll: [u8; 64],
        inventory: [u8; 64],
        target: [u8; 64],
        position: usize,
        length: usize,
        identity: [u8; 64],
    ) -> Result<Self, Error> {
        if position >= profile.participants() || !body_lengths(profile).contains(&length) {
            return Err(Error::Shape);
        }
        let mut bytes = Vec::from(b"LRE1".as_slice());
        bytes.extend(poll);
        bytes.extend(inventory);
        bytes.extend(target);
        bytes.extend((position as u16).to_le_bytes());
        bytes.extend((length as u64).to_le_bytes());
        bytes.extend(identity);
        Ok(Self {
            bytes,
            poll,
            inventory,
            target,
            position,
            length,
            identity,
        })
    }
    pub fn decode(profile: Profile, bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RELEASE_ENVELOPE_BYTES || &bytes[..4] != b"LRE1" {
            return Err(Error::Shape);
        }
        let length = usize::try_from(u64::from_le_bytes(bytes[198..206].try_into().unwrap()))
            .map_err(|_| Error::Shape)?;
        Self::new(
            profile,
            bytes[4..68].try_into().unwrap(),
            bytes[68..132].try_into().unwrap(),
            bytes[132..196].try_into().unwrap(),
            u16::from_le_bytes(bytes[196..198].try_into().unwrap()) as usize,
            length,
            bytes[206..].try_into().unwrap(),
        )
    }
    pub fn bytes(&self) -> &[u8] {
        &self.bytes
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
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
) -> Result<Vec<u8>, Error> {
    if header_position(profile, context).is_none() || !proof_lengths(profile).contains(&proof_bytes)
    {
        return Err(Error::Shape);
    }
    let mut bytes = Vec::from(b"LRB1".as_slice());
    bytes.extend((proof_bytes as u64).to_le_bytes());
    bytes.extend(context);
    Ok(bytes)
}
pub fn proof_length(profile: Profile, header: &[u8]) -> Result<usize, Error> {
    if header.len() != RELEASE_BODY_HEADER_BYTES || &header[..4] != b"LRB1" {
        return Err(Error::Shape);
    }
    let proof = usize::try_from(u64::from_le_bytes(header[4..12].try_into().unwrap()))
        .map_err(|_| Error::Shape)?;
    if body_header(profile, header[12..].try_into().unwrap(), proof)? != header {
        return Err(Error::Shape);
    }
    Ok(proof)
}
/// The hasher of a release body of the length.
pub fn body_hasher(profile: Profile, length: usize) -> Result<BodyHasher, Error> {
    if !body_lengths(profile).contains(&length) {
        return Err(Error::Shape);
    }
    BodyHasher::new("sealed-lattice/release-body/v1", length)
}

impl Credential {
    pub fn begin_release(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
    ) -> Result<(), Error> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        self.check_unlocked(SigningPurpose::Release)?;
        if !message.encrypted()
            || self.release_started
            || self
                .target_lock
                .is_some_and(|target| target != *message.identity())
        {
            return Err(Error::Consumed);
        }
        self.target_lock = Some(*message.identity());
        self.release_started = true;
        Ok(())
    }
    pub fn sign_release(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        envelope: &ReleaseEnvelope,
    ) -> Result<[u8; SIGNATURE_BYTES], Error> {
        self.check_ballot_owner(owner)?;
        self.check_target_predecessors(owner, roster)?;
        let record = roster
            .proposal()
            .records()
            .get(owner.position())
            .ok_or(Error::Context)?;
        if !self.release_started || self.release_signed {
            return Err(Error::Consumed);
        }
        if self.target_lock.as_ref() != Some(envelope.target())
            || envelope.poll() != owner.poll()
            || envelope.inventory() != owner.inventory()
            || envelope.position() != owner.position()
            || record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
        {
            return Err(Error::Context);
        }
        self.release_signed = true;
        self.sign_deterministically(envelope.bytes(), RELEASE_SIGNATURE_CONTEXT)
    }
    pub fn restore_release(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
        envelope: &ReleaseEnvelope,
        signature: &[u8],
    ) -> Result<(), Error> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        if !message.encrypted() || self.release_started || self.release_signed {
            return Err(Error::Consumed);
        }
        if envelope.poll() != owner.poll()
            || envelope.inventory() != owner.inventory()
            || envelope.position() != owner.position()
            || envelope.target() != message.identity()
            || self
                .target_lock
                .is_some_and(|target| target != *message.identity())
        {
            return Err(Error::Context);
        }
        let signature = signature.try_into().map_err(|_| Error::Shape)?;
        let key =
            ml_dsa_65::PublicKey::try_from_bytes(self.signing_public).map_err(|_| Error::Crypto)?;
        if !key.verify(envelope.bytes(), &signature, RELEASE_SIGNATURE_CONTEXT) {
            return Err(Error::Crypto);
        }
        self.target_lock = Some(*message.identity());
        self.release_started = true;
        self.release_signed = true;
        Ok(())
    }
}

#[cfg(test)]
#[path = "release-signing-tests.rs"]
mod tests;
