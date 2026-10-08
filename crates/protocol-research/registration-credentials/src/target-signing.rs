use crate::{
    Credential, Error, SIGNATURE_BYTES, SigningPurpose,
    ballot_authentication::RetainedBallotOwner,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{SerDes, Verifier},
};
use supported_profile::Profile;

pub const TARGET_PURPOSE: &str = "sealed-lattice/evaluation-target/v1";
pub const TARGET_IDENTITY_DOMAIN: &str = "sealed-lattice/evaluation-target-id/v1";
pub const CERTIFICATION_CONTEXT: &[u8] = b"sealed-lattice/target-certification/v1";
pub const TARGET_VOTE_BYTES: usize = 2 + 64 + crate::SIGNATURE_BYTES;
/// Every evaluation target body is at most this long.
pub const MAXIMUM_TARGET_BODY_BYTES: usize = 2048;

/// A result needs at least `f+2` accepted ballots, where `f = floor((n-1)/3)`
/// bounds the compromised participants, so every result combines at least two
/// honest ballots. A smaller accepted set takes the no-result branch.
pub fn minimum_turnout(participants: usize) -> usize {
    participants.saturating_sub(1) / 3 + 2
}

/// Canonical signing data only. Parsing this value never verifies evaluation,
/// the source inventory, certification or authority to release a share.
pub struct TargetMessage {
    body: Vec<u8>,
    poll: [u8; 64],
    inventory: [u8; 64],
    proposal: [u8; 64],
    identity: [u8; 64],
    participants: usize,
    encrypted: bool,
    classifications: Vec<u8>,
}
impl TargetMessage {
    pub fn parse(body: &[u8], participants: usize) -> Result<Self, Error> {
        if !Profile::participant_range().contains(&participants) {
            return Err(Error::Context);
        }
        // Classification codes: 0 absent, 1 invalid, 2 accepted, 3 conflicting.
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: MAXIMUM_TARGET_BODY_BYTES,
            maximum_item_count: 9,
            maximum_item_byte_length: MAXIMUM_TARGET_BODY_BYTES,
            maximum_nesting_depth: 0,
            ..CanonicalDecodeLimits::default()
        };
        let tuple = CanonicalTuple::decode(body, &limits).map_err(|_| Error::Shape)?;
        if tuple.schema_identifier != 1
            || tuple.schema_version != 1
            || ![6, 9].contains(&tuple.items.len())
        {
            return Err(Error::Shape);
        }
        let items = &tuple.items;
        if items[0].item_type() != CanonicalItemType::Ascii
            || items[0].variable_value_bytes().map_err(|_| Error::Shape)?
                != TARGET_PURPOSE.as_bytes()
        {
            return Err(Error::Context);
        }
        if items[1..4]
            .iter()
            .any(|item| item.item_type() != CanonicalItemType::Hash512)
            || items[4].item_type() != CanonicalItemType::RawBytes
            || items[5].item_type() != CanonicalItemType::Unsigned16
        {
            return Err(Error::Shape);
        }
        let classifications = items[4].variable_value_bytes().map_err(|_| Error::Shape)?;
        if classifications.len() != participants || classifications.iter().any(|value| *value > 3) {
            return Err(Error::Shape);
        }
        let branch = u16::from_le_bytes(
            items[5]
                .canonical_bytes()
                .try_into()
                .map_err(|_| Error::Shape)?,
        );
        let accepted = classifications.iter().filter(|value| **value == 2).count();
        let evaluated = accepted >= minimum_turnout(participants);
        match branch {
            0 if items.len() == 6 && !evaluated => {}
            1 if items.len() == 9 && evaluated => {
                if items[6..8]
                    .iter()
                    .any(|item| item.item_type() != CanonicalItemType::Hash512)
                    || items[8].item_type() != CanonicalItemType::Unsigned64
                {
                    return Err(Error::Shape);
                }
                if u64::from_le_bytes(
                    items[8]
                        .canonical_bytes()
                        .try_into()
                        .map_err(|_| Error::Shape)?,
                ) == 0
                {
                    return Err(Error::Shape);
                }
            }
            _ => return Err(Error::Shape),
        }
        let identity = hash_foundation_tuple_512(
            TARGET_IDENTITY_DOMAIN,
            &[CanonicalItem::variable_bytes(body).map_err(|_| Error::Shape)?],
        )
        .map_err(|_| Error::Shape)?
        .into_bytes();
        Ok(Self {
            body: body.to_vec(),
            poll: items[1]
                .canonical_bytes()
                .try_into()
                .map_err(|_| Error::Shape)?,
            inventory: items[2]
                .canonical_bytes()
                .try_into()
                .map_err(|_| Error::Shape)?,
            proposal: items[3]
                .canonical_bytes()
                .try_into()
                .map_err(|_| Error::Shape)?,
            identity,
            participants,
            encrypted: branch == 1,
            classifications: classifications.to_vec(),
        })
    }
    pub fn body(&self) -> &[u8] {
        &self.body
    }
    pub fn identity(&self) -> &[u8; 64] {
        &self.identity
    }
    pub fn poll(&self) -> &[u8; 64] {
        &self.poll
    }
    /// The identity of the close proposal whose barrier the target was
    /// evaluated from.
    pub fn proposal(&self) -> &[u8; 64] {
        &self.proposal
    }
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn participants(&self) -> usize {
        self.participants
    }
    pub fn encrypted(&self) -> bool {
        self.encrypted
    }
    /// A participant's classification code, or `None` outside the roster.
    pub fn classification(&self, position: usize) -> Option<u8> {
        self.classifications.get(position).copied()
    }
}

/// A fixed-size authenticated transport message. Its target must still be
/// supplied by the owning evaluation verifier before it can certify anything.
#[derive(Clone)]
pub struct TargetVote {
    position: usize,
    target: [u8; 64],
    signature: [u8; SIGNATURE_BYTES],
}
impl TargetVote {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TARGET_VOTE_BYTES {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
        // A position lies within the largest supported roster.
        if position >= *Profile::participant_range().end() {
            return Err(Error::Shape);
        }
        Ok(Self {
            position,
            target: bytes[2..66].try_into().unwrap(),
            signature: bytes[66..].try_into().unwrap(),
        })
    }
    pub fn position(&self) -> usize {
        self.position
    }
    pub fn target(&self) -> &[u8; 64] {
        &self.target
    }
    pub fn signature(&self) -> &[u8; SIGNATURE_BYTES] {
        &self.signature
    }
    pub fn encode(&self) -> Vec<u8> {
        let mut bytes = Vec::from((self.position as u16).to_le_bytes());
        bytes.extend(self.target);
        bytes.extend(self.signature);
        bytes
    }
}

impl Credential {
    pub(crate) fn check_target_owner(
        &self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
    ) -> Result<(), Error> {
        self.check_ballot_owner(owner)?;
        let records = roster.proposal().records();
        let record = records.get(owner.position()).ok_or(Error::Context)?;
        if records.len() != message.participants
            || message.poll() != owner.poll()
            || message.inventory() != owner.inventory()
            || record.header().signing_public != self.signing_public
            || self.completed_body != Some(record.body_digest())
            || self
                .target_lock
                .is_some_and(|target| target != *message.identity())
        {
            return Err(Error::Context);
        }
        Ok(())
    }
    /// A target signer has responded to the close; the organizer has also
    /// proposed. Its own ballot need not be included.
    pub(crate) fn check_target_predecessors(
        &self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
    ) -> Result<(), Error> {
        if self.close_response.is_none()
            || (owner.position() == roster.proposal().organizer_position()
                && !self.close_proposal_signed)
        {
            return Err(Error::Consumed);
        }
        Ok(())
    }
    /// Volatile one-shot signing beneath the authenticated participant root.
    /// The enrollment bridge supplies a genuinely evaluated target and commits
    /// its exact exact body before reaching this method.
    pub fn sign_target(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
    ) -> Result<TargetVote, Error> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        self.check_unlocked(SigningPurpose::Target)?;
        if self.target_signed {
            return Err(Error::Consumed);
        }
        self.target_signed = true;
        self.target_lock = Some(*message.identity());
        let signature = self.sign_deterministically(message.identity(), CERTIFICATION_CONTEXT)?;
        Ok(TargetVote {
            position: owner.position(),
            target: *message.identity(),
            signature,
        })
    }
    /// Restores consumed target authority from the exact authenticated root
    /// record. It verifies the retained vote's signature under the credential,
    /// signs nothing and never reopens that purpose.
    pub fn restore_target(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
        packet: &[u8],
    ) -> Result<(), Error> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        if self.target_signed {
            return Err(Error::Consumed);
        }
        let vote = TargetVote::parse(packet)?;
        let key =
            ml_dsa_65::PublicKey::try_from_bytes(self.signing_public).map_err(|_| Error::Crypto)?;
        if vote.position() != owner.position()
            || vote.target() != message.identity()
            || !key.verify(message.identity(), vote.signature(), CERTIFICATION_CONTEXT)
        {
            return Err(Error::Crypto);
        }
        self.target_signed = true;
        self.target_lock = Some(*message.identity());
        Ok(())
    }
}

#[cfg(test)]
#[path = "target-signing-tests.rs"]
mod tests;
