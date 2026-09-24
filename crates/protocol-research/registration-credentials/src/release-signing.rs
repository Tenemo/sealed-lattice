use crate::{
    Credential, Error, SigningPurpose, ballot_authentication::RetainedBallotOwner,
    foundation::hash::StreamingFoundationTupleHash512,
    roster_authentication::OrganizerSignedRoster, target_signing::TargetMessage,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use linked_release_proof::{
    HEADER_LENGTH,
    parameters::{HEADER_BYTES, MAXIMUM_PROOF_BYTES, SYSTEMATIC},
};
use zeroize::Zeroizing;

pub const RELEASE_SIGNATURE_CONTEXT: &[u8] = b"sealed-lattice/release-envelope/v1";
pub const RELEASE_ENVELOPE_BYTES: usize = 4 + 3 * 64 + 2 + 8 + 64;
pub const RELEASE_BODY_HEADER_BYTES: usize = 12 + HEADER_BYTES;
pub const PARTIAL_BYTES: usize = SYSTEMATIC * 25;
pub const MAXIMUM_BODY_BYTES: usize =
    RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES + MAXIMUM_PROOF_BYTES;

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
        poll: [u8; 64],
        inventory: [u8; 64],
        target: [u8; 64],
        position: usize,
        length: usize,
        identity: [u8; 64],
    ) -> Result<Self, Error> {
        if position >= 20
            || !(RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES + HEADER_LENGTH..=MAXIMUM_BODY_BYTES)
                .contains(&length)
        {
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
    pub fn decode(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != RELEASE_ENVELOPE_BYTES || &bytes[..4] != b"LRE1" {
            return Err(Error::Shape);
        }
        let length = usize::try_from(u64::from_le_bytes(bytes[198..206].try_into().unwrap()))
            .map_err(|_| Error::Shape)?;
        Self::new(
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

pub fn body_header(context: &[u8; HEADER_BYTES], proof_bytes: usize) -> Result<Vec<u8>, Error> {
    if &context[..4] != b"LRS1"
        || u16::from_le_bytes(context[196..].try_into().unwrap()) >= 10
        || !(HEADER_LENGTH..=MAXIMUM_PROOF_BYTES).contains(&proof_bytes)
    {
        return Err(Error::Shape);
    }
    let mut bytes = Vec::from(b"LRB1".as_slice());
    bytes.extend((proof_bytes as u64).to_le_bytes());
    bytes.extend(context);
    Ok(bytes)
}
pub fn proof_length(header: &[u8]) -> Result<usize, Error> {
    if header.len() != RELEASE_BODY_HEADER_BYTES || &header[..4] != b"LRB1" {
        return Err(Error::Shape);
    }
    let proof = usize::try_from(u64::from_le_bytes(header[4..12].try_into().unwrap()))
        .map_err(|_| Error::Shape)?;
    if body_header(header[12..].try_into().unwrap(), proof)? != header {
        return Err(Error::Shape);
    }
    Ok(proof)
}
pub struct ReleaseBodyHasher {
    hash: Option<StreamingFoundationTupleHash512>,
    remaining: usize,
}
impl ReleaseBodyHasher {
    pub fn new(length: usize) -> Result<Self, Error> {
        if !(RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES + HEADER_LENGTH..=MAXIMUM_BODY_BYTES)
            .contains(&length)
        {
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

    fn context() -> [u8; HEADER_BYTES] {
        let mut context = [0; HEADER_BYTES];
        context[..4].copy_from_slice(b"LRS1");
        context[4..68].fill(1);
        context[68..132].fill(2);
        context[132..196].fill(3);
        context[196..].copy_from_slice(&9u16.to_le_bytes());
        context
    }
    #[test]
    fn release_framing_bounds_context_and_exact_body_length() {
        let minimum = RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES + HEADER_LENGTH;
        for length in [minimum, MAXIMUM_BODY_BYTES] {
            let envelope =
                ReleaseEnvelope::new([1; 64], [2; 64], [3; 64], 9, length, [4; 64]).unwrap();
            assert_eq!(
                ReleaseEnvelope::decode(envelope.bytes()).unwrap().bytes(),
                envelope.bytes()
            );
            assert!(
                ReleaseEnvelope::decode(&envelope.bytes()[..RELEASE_ENVELOPE_BYTES - 1]).is_err()
            );
            let mut excess = envelope.bytes().to_vec();
            excess.push(0);
            assert!(ReleaseEnvelope::decode(&excess).is_err());
            let mut changed = envelope.bytes().to_vec();
            changed[196..198].copy_from_slice(&20u16.to_le_bytes());
            assert!(ReleaseEnvelope::decode(&changed).is_err());
            changed = envelope.bytes().to_vec();
            changed[198..206].copy_from_slice(&u64::MAX.to_le_bytes());
            assert!(ReleaseEnvelope::decode(&changed).is_err());
        }
        for length in [minimum - 1, MAXIMUM_BODY_BYTES + 1, usize::MAX] {
            assert!(ReleaseEnvelope::new([1; 64], [2; 64], [3; 64], 0, length, [4; 64]).is_err());
            assert!(ReleaseBodyHasher::new(length).is_err());
        }
        for length in [HEADER_LENGTH, MAXIMUM_PROOF_BYTES] {
            let bytes = body_header(&context(), length).unwrap();
            assert_eq!(proof_length(&bytes).unwrap(), length);
            let mut changed = bytes.clone();
            changed.push(0);
            assert!(proof_length(&changed).is_err());
            assert!(proof_length(&bytes[..bytes.len() - 1]).is_err());
            for offset in [0, 12] {
                let mut changed = bytes.clone();
                changed[offset] ^= 1;
                assert!(proof_length(&changed).is_err());
            }
        }
        for length in [HEADER_LENGTH - 1, MAXIMUM_PROOF_BYTES + 1, usize::MAX] {
            assert!(body_header(&context(), length).is_err());
        }
        let mut wrong = context();
        wrong[196..].copy_from_slice(&10u16.to_le_bytes());
        assert!(body_header(&wrong, HEADER_LENGTH).is_err());
    }
    #[test]
    fn release_digest_matches_canonical_hash_across_chunk_boundaries() {
        let mut body = body_header(&context(), HEADER_LENGTH).unwrap();
        body.extend((0..PARTIAL_BYTES + HEADER_LENGTH).map(|index| (index % 251) as u8));
        let expected = hash_foundation_tuple_512(
            "sealed-lattice/release-body/v1",
            &[CanonicalItem::variable_bytes(&body).unwrap()],
        )
        .unwrap()
        .into_bytes();
        for chunk_size in [4093, 1 << 20] {
            let mut hasher = ReleaseBodyHasher::new(body.len()).unwrap();
            for chunk in body.chunks(chunk_size) {
                hasher.push(chunk).unwrap();
            }
            assert_eq!(hasher.finish().unwrap(), expected);
        }
        let mut changed = body.clone();
        changed[RELEASE_BODY_HEADER_BYTES + PARTIAL_BYTES - 1] ^= 1;
        let mut hasher = ReleaseBodyHasher::new(changed.len()).unwrap();
        for chunk in changed.chunks(1 << 20) {
            hasher.push(chunk).unwrap();
        }
        assert_ne!(hasher.finish().unwrap(), expected);
        let mut hasher = ReleaseBodyHasher::new(body.len()).unwrap();
        for chunk in body.chunks(1 << 20) {
            hasher.push(chunk).unwrap();
        }
        assert!(hasher.push(&[0]).is_err());
        assert!(hasher.finish().is_err());
        for invalid in [Vec::new(), vec![0; (1 << 20) + 1]] {
            let mut hasher = ReleaseBodyHasher::new(body.len()).unwrap();
            assert!(hasher.push(&invalid).is_err());
            assert!(hasher.finish().is_err());
        }
        assert!(
            ReleaseBodyHasher::new(body.len())
                .unwrap()
                .finish()
                .is_err()
        );
    }
}
