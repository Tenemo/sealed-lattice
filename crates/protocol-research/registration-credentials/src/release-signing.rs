use crate::{
    Credential, Error, SigningPurpose, ballot_authentication::RetainedBallotOwner,
    foundation::hash::StreamingFoundationTupleHash512,
    roster_authentication::OrganizerSignedRoster, target_signing::TargetMessage,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use linked_release_proof::statement::{header_position, release_coefficient_bytes};
use std::ops::RangeInclusive;
use supported_profile::{
    Profile,
    relation::{PROOF_HEADER_BYTES, RELEASE_HEADER_BYTES, SYSTEMATIC, release_relation},
};
use zeroize::Zeroizing;

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
pub struct ReleaseBodyHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    remaining: usize,
}
impl ReleaseBodyHasher {
    pub fn new(profile: Profile, length: usize) -> Result<Self, Error> {
        if !body_lengths(profile).contains(&length) {
            return Err(Error::Shape);
        }
        Ok(Self {
            hash: Some(
                StreamingFoundationTupleHash512::new_variable_bytes(
                    "sealed-lattice/release-body/v1",
                    &[],
                    length,
                )
                .map_err(|_| Error::Shape)?,
            ),
            remaining: length,
        })
    }
    pub fn push(&mut self, bytes: &[u8]) -> Result<(), Error> {
        if bytes.is_empty() || bytes.len() > 1 << 20 || bytes.len() > self.remaining {
            self.hash = None;
            return Err(Error::Shape);
        }
        self.hash
            .as_mut()
            .ok_or(Error::Shape)?
            .absorb(bytes)
            .map_err(|_| Error::Shape)?;
        self.remaining -= bytes.len();
        Ok(())
    }
    pub fn finish(self) -> Result<[u8; 64], Error> {
        if self.remaining != 0 {
            return Err(Error::Shape);
        }
        self.hash
            .ok_or(Error::Shape)?
            .finalize()
            .map(|value| value.into_bytes())
            .map_err(|_| Error::Shape)
    }
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
        coins: [u8; 32],
    ) -> Result<[u8; 3309], Error> {
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
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        key.try_sign_with_seed(&coins, envelope.bytes(), RELEASE_SIGNATURE_CONTEXT)
            .map_err(|_| Error::Crypto)
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
mod tests {
    use super::*;
    use crate::foundation::{CanonicalItem, hash_foundation_tuple_512};

    fn context(position: usize) -> [u8; RELEASE_HEADER_BYTES] {
        let mut context = [0; RELEASE_HEADER_BYTES];
        context[..4].copy_from_slice(b"LRS1");
        context[4..68].fill(1);
        context[68..132].fill(2);
        context[132..196].fill(3);
        context[196..].copy_from_slice(&(position as u16).to_le_bytes());
        context
    }
    #[test]
    fn release_framing_bounds_context_and_exact_body_length() {
        for (participants, options) in [(3, 2), (20, 20)] {
            let profile = Profile::new(participants, options).unwrap();
            let last = participants - 1;
            let bodies = body_lengths(profile);
            for length in [*bodies.start(), *bodies.end()] {
                let envelope =
                    ReleaseEnvelope::new(profile, [1; 64], [2; 64], [3; 64], last, length, [4; 64])
                        .unwrap();
                assert_eq!(
                    ReleaseEnvelope::decode(profile, envelope.bytes())
                        .unwrap()
                        .bytes(),
                    envelope.bytes()
                );
                assert!(
                    ReleaseEnvelope::decode(
                        profile,
                        &envelope.bytes()[..RELEASE_ENVELOPE_BYTES - 1]
                    )
                    .is_err()
                );
                let mut excess = envelope.bytes().to_vec();
                excess.push(0);
                assert!(ReleaseEnvelope::decode(profile, &excess).is_err());
                let mut changed = envelope.bytes().to_vec();
                changed[196..198].copy_from_slice(&(participants as u16).to_le_bytes());
                assert!(ReleaseEnvelope::decode(profile, &changed).is_err());
                changed = envelope.bytes().to_vec();
                changed[198..206].copy_from_slice(&u64::MAX.to_le_bytes());
                assert!(ReleaseEnvelope::decode(profile, &changed).is_err());
            }
            for length in [bodies.start() - 1, bodies.end() + 1, usize::MAX] {
                assert!(
                    ReleaseEnvelope::new(profile, [1; 64], [2; 64], [3; 64], 0, length, [4; 64])
                        .is_err()
                );
                assert!(ReleaseBodyHasher::new(profile, length).is_err());
            }
            let proofs = proof_lengths(profile);
            for length in [*proofs.start(), *proofs.end()] {
                let bytes = body_header(profile, &context(last), length).unwrap();
                assert_eq!(proof_length(profile, &bytes).unwrap(), length);
                let mut changed = bytes.clone();
                changed.push(0);
                assert!(proof_length(profile, &changed).is_err());
                assert!(proof_length(profile, &bytes[..bytes.len() - 1]).is_err());
                for offset in [0, 12] {
                    let mut changed = bytes.clone();
                    changed[offset] ^= 1;
                    assert!(proof_length(profile, &changed).is_err());
                }
            }
            for length in [proofs.start() - 1, proofs.end() + 1, usize::MAX] {
                assert!(body_header(profile, &context(last), length).is_err());
            }
            assert!(body_header(profile, &context(participants), *proofs.start()).is_err());
        }
        // A three-participant header names no position of another roster's
        // last participant, and every release body carries a 25-byte
        // coefficient per row of the completion profile's partial.
        let small = Profile::new(3, 2).unwrap();
        let wide = Profile::new(20, 20).unwrap();
        let header = body_header(wide, &context(19), PROOF_HEADER_BYTES).unwrap();
        assert!(proof_length(small, &header).is_err());
        assert_eq!(partial_bytes(Profile::new(10, 10).unwrap()), 65_536 * 25);
    }
    #[test]
    fn release_digest_matches_canonical_hash_across_chunk_boundaries() {
        let profile = Profile::new(3, 2).unwrap();
        let partial = partial_bytes(profile);
        let mut body = body_header(profile, &context(0), PROOF_HEADER_BYTES).unwrap();
        body.extend((0..partial + PROOF_HEADER_BYTES).map(|index| (index % 251) as u8));
        let expected = hash_foundation_tuple_512(
            "sealed-lattice/release-body/v1",
            &[CanonicalItem::variable_bytes(&body).unwrap()],
        )
        .unwrap()
        .into_bytes();
        for chunk_size in [4093, 1 << 20] {
            let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
            for chunk in body.chunks(chunk_size) {
                hasher.push(chunk).unwrap();
            }
            assert_eq!(hasher.finish().unwrap(), expected);
        }
        let mut changed = body.clone();
        changed[RELEASE_BODY_HEADER_BYTES + partial - 1] ^= 1;
        let mut hasher = ReleaseBodyHasher::new(profile, changed.len()).unwrap();
        for chunk in changed.chunks(1 << 20) {
            hasher.push(chunk).unwrap();
        }
        assert_ne!(hasher.finish().unwrap(), expected);
        let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
        for chunk in body.chunks(1 << 20) {
            hasher.push(chunk).unwrap();
        }
        assert!(hasher.push(&[0]).is_err());
        assert!(hasher.finish().is_err());
        for invalid in [Vec::new(), vec![0; (1 << 20) + 1]] {
            let mut hasher = ReleaseBodyHasher::new(profile, body.len()).unwrap();
            assert!(hasher.push(&invalid).is_err());
            assert!(hasher.finish().is_err());
        }
        assert!(
            ReleaseBodyHasher::new(profile, body.len())
                .unwrap()
                .finish()
                .is_err()
        );
    }
}
