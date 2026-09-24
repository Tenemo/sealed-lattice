use crate::{
    Credential, Error, SigningPurpose,
    ballot_authentication::RetainedBallotOwner,
    foundation::{
        CanonicalDecodeLimits, CanonicalItem, CanonicalItemType, CanonicalTuple,
        hash_foundation_tuple_512,
    },
    roster_authentication::OrganizerSignedRoster,
};
use fips204::{
    ml_dsa_65,
    traits::{KeyGen, SerDes, Signer, Verifier},
};
use zeroize::Zeroizing;

pub const TARGET_PURPOSE: &str = "sealed-lattice/evaluation-target/v1";
pub const TARGET_IDENTITY_DOMAIN: &str = "sealed-lattice/evaluation-target-id/v1";
pub const CERTIFICATION_CONTEXT: &[u8] = b"sealed-lattice/target-certification/v1";
pub const TARGET_VOTE_BYTES: usize = 2 + 64 + 3309;

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
    identity: [u8; 64],
    participants: usize,
    encrypted: bool,
}
impl TargetMessage {
    pub fn parse(body: &[u8], participants: usize) -> Result<Self, Error> {
        if !(3..=20).contains(&participants) {
            return Err(Error::Context);
        }
        // Classification codes: 0 absent, 1 invalid, 2 accepted, 3 conflicting.
        let limits = CanonicalDecodeLimits {
            maximum_tuple_byte_length: 2048,
            maximum_item_count: 9,
            maximum_item_byte_length: 2048,
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
            identity,
            participants,
            encrypted: branch == 1,
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
    pub fn inventory(&self) -> &[u8; 64] {
        &self.inventory
    }
    pub fn participants(&self) -> usize {
        self.participants
    }
    pub fn encrypted(&self) -> bool {
        self.encrypted
    }
}

/// A fixed-size authenticated transport message. Its target must still be
/// supplied by the owning evaluation verifier before it can certify anything.
#[derive(Clone)]
pub struct TargetVote {
    position: usize,
    target: [u8; 64],
    signature: [u8; 3309],
}
impl TargetVote {
    pub fn parse(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.len() != TARGET_VOTE_BYTES {
            return Err(Error::Shape);
        }
        let position = u16::from_le_bytes(bytes[..2].try_into().unwrap()) as usize;
        if position >= 20 {
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
    pub fn signature(&self) -> &[u8; 3309] {
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
    /// its exact body and coins before reaching this method.
    pub fn sign_target(
        &mut self,
        owner: &RetainedBallotOwner,
        roster: &OrganizerSignedRoster,
        message: &TargetMessage,
        coins: [u8; 32],
    ) -> Result<TargetVote, Error> {
        self.check_target_owner(owner, roster, message)?;
        self.check_target_predecessors(owner, roster)?;
        self.check_unlocked(SigningPurpose::Target)?;
        if self.target_signed {
            return Err(Error::Consumed);
        }
        self.target_signed = true;
        self.target_lock = Some(*message.identity());
        let coins = Zeroizing::new(coins);
        let (_, key) = ml_dsa_65::KG::keygen_from_seed(&self.signing_seed);
        let signature = key
            .try_sign_with_seed(&coins, message.identity(), CERTIFICATION_CONTEXT)
            .map_err(|_| Error::Crypto)?;
        Ok(TargetVote {
            position: owner.position(),
            target: *message.identity(),
            signature,
        })
    }
    /// Restores consumed target authority from the exact authenticated root
    /// record, without evaluating another signature or reopening that purpose.
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
mod tests {
    use super::*;
    // Absent, invalid and conflicting classifications cycle after the accepted ones.
    fn body(participants: usize, accepted: usize, evaluated: bool) -> Vec<u8> {
        let classifications: Vec<u8> = (0..participants)
            .map(|position| {
                if position < accepted {
                    2
                } else {
                    [0, 1, 3][position % 3]
                }
            })
            .collect();
        let mut items = vec![
            CanonicalItem::nonempty_ascii(TARGET_PURPOSE).unwrap(),
            CanonicalItem::hash512([1; 64]),
            CanonicalItem::hash512([2; 64]),
            CanonicalItem::hash512([3; 64]),
            CanonicalItem::variable_bytes(&classifications).unwrap(),
            CanonicalItem::unsigned16(u16::from(evaluated)),
        ];
        if evaluated {
            items.extend([
                CanonicalItem::hash512([4; 64]),
                CanonicalItem::hash512([5; 64]),
                CanonicalItem::unsigned64(3276800),
            ]);
        }
        CanonicalTuple::new(1, 1, items).encode().unwrap()
    }
    #[test]
    fn minimum_turnout_is_two_more_than_the_compromise_bound() {
        for (participants, turnout) in [(3, 2), (4, 3), (6, 3), (7, 4), (10, 5), (13, 6), (20, 8)] {
            assert_eq!(minimum_turnout(participants), turnout);
        }
    }
    #[test]
    fn only_the_minimum_turnout_selects_the_evaluated_branch() {
        for participants in 3..=20 {
            let minimum = minimum_turnout(participants);
            for accepted in 0..=participants {
                let evaluated = accepted >= minimum;
                let message =
                    TargetMessage::parse(&body(participants, accepted, evaluated), participants)
                        .unwrap();
                assert_eq!(message.encrypted(), evaluated);
                assert!(
                    TargetMessage::parse(&body(participants, accepted, !evaluated), participants)
                        .is_err(),
                    "participants={participants}, accepted={accepted}"
                );
            }
        }
    }
    #[test]
    fn signing_data_is_canonical_and_cannot_switch_branch_or_roster_shape() {
        for participants in 3..=20 {
            for evaluated in [false, true] {
                let accepted = if evaluated { participants } else { 0 };
                let bytes = body(participants, accepted, evaluated);
                let message = TargetMessage::parse(&bytes, participants).unwrap();
                assert_eq!(message.body(), bytes);
                assert!(
                    TargetMessage::parse(
                        &bytes,
                        if participants == 20 {
                            19
                        } else {
                            participants + 1
                        }
                    )
                    .is_err()
                );
                let mut excess = bytes.clone();
                excess.push(0);
                assert!(TargetMessage::parse(&excess, participants).is_err());
                let mut tuple =
                    CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
                let mut classifications = tuple.items[4].variable_value_bytes().unwrap().to_vec();
                classifications[participants - 1] = 4;
                tuple.items[4] = CanonicalItem::variable_bytes(&classifications).unwrap();
                assert!(TargetMessage::parse(&tuple.encode().unwrap(), participants).is_err());
                let mut tuple =
                    CanonicalTuple::decode(&bytes, &CanonicalDecodeLimits::default()).unwrap();
                tuple.items[5] = CanonicalItem::unsigned16(u16::from(!evaluated));
                assert!(TargetMessage::parse(&tuple.encode().unwrap(), participants).is_err());
            }
        }
    }
    #[test]
    fn vote_framing_refuses_missing_extra_and_out_of_range_data() {
        let value = TargetVote {
            position: 19,
            target: [6; 64],
            signature: [7; 3309],
        };
        let bytes = value.encode();
        assert_eq!(TargetVote::parse(&bytes).unwrap().encode(), bytes);
        assert!(TargetVote::parse(&bytes[..bytes.len() - 1]).is_err());
        let mut changed = bytes.clone();
        changed.push(0);
        assert!(TargetVote::parse(&changed).is_err());
        let mut changed = bytes;
        changed[..2].copy_from_slice(&20u16.to_le_bytes());
        assert!(TargetVote::parse(&changed).is_err());
    }
}
